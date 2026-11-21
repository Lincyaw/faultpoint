import { readFileSync } from "node:fs";

import { context } from "@opentelemetry/api";
import { z } from "zod";

import { applicationModule } from "./config.js";
import { CORE, type Plugin, errorName } from "./core.js";
import { numberParameter, pointId } from "./rules.js";

/** spec/redis-commands.json, which the build copies next to this module. */
const RedisCommand = z.object({
  kind: z.enum(["store_read", "store_write", "publish", "consume"]),
  key: z.union([z.number().int(), z.string(), z.null()]),
  empty: z.enum(["nil", "empty_array", "empty_string", "zero", "all_nil", "never"]).optional(),
});
type RedisCommand = z.infer<typeof RedisCommand>;
const TABLE = z.object({ key_identifier: z.string(), commands: z.record(z.string(), RedisCommand) })
  .parse(JSON.parse(readFileSync(new URL("./redis-commands.json", import.meta.url), "utf-8")));

export const IoredisOptions = z.strictObject({ key_identifier: z.string().default(TABLE.key_identifier) });

/** The part of an ioredis Command the adapter uses. */
interface Command {
  name: string;
  args: unknown[];
  promise: Promise<unknown>;
  resolve(value: unknown): void;
  reject(error: Error): void;
  [HANDLED]?: boolean;
}

type SendCommand = (this: unknown, command: Command, stream?: unknown) => unknown;

/** A command a cluster routes to a node passes sendCommand twice; it is one point. */
const HANDLED = Symbol("faultpoint.handled");

function text(argument: unknown): string {
  return Buffer.isBuffer(argument) ? argument.toString("utf-8") : String(argument);
}

/** The key of a command by the table's rule: an index, the argument after a token, or after a key count. */
function keyOf(rule: RedisCommand["key"], args: unknown[]): string | null {
  if (typeof rule === "number") {
    return rule < args.length ? text(args[rule]) : null;
  }
  if (typeof rule === "string" && rule.startsWith("after:")) {
    const token = rule.slice("after:".length).toUpperCase();
    const index = args.findIndex((argument) => text(argument).toUpperCase() === token);
    return index >= 0 && index + 1 < args.length ? text(args[index + 1]) : null;
  }
  if (typeof rule === "string" && rule.startsWith("numkeys:")) {
    const at = Number(rule.slice("numkeys:".length));
    return Number(text(args[at])) > 0 && at + 1 < args.length ? text(args[at + 1]) : null;
  }
  return null;
}

/** Whether a reply is empty by the command's rule; ioredis gives nil as null and an empty array as []. */
function empty(rule: RedisCommand["empty"], reply: unknown): boolean {
  switch (rule) {
    case "nil":
      return reply === null || reply === undefined || (Array.isArray(reply) && reply.length === 0);
    case "empty_array":
      return reply === null || (Array.isArray(reply) ? reply.length === 0 : typeof reply === "object" && Object.keys(reply as object).length === 0);
    case "empty_string":
      return reply === null || reply === "" || (Buffer.isBuffer(reply) && reply.length === 0);
    case "zero":
      return reply === null || reply === 0;
    case "all_nil":
      return Array.isArray(reply) && reply.every((element) => element === null);
    default:
      return false;
  }
}

/** The reply an empty rule answers with, in the shape the command's rule recognises as empty. */
function emptyReply(name: string, rule: RedisCommand["empty"], args: unknown[]): unknown {
  switch (rule) {
    case "empty_array":
      return [];
    case "empty_string":
      return "";
    case "zero":
      return 0;
    case "all_nil":
      return args.slice(name === "MGET" ? 0 : 1).map(() => null);
    default:
      return null;
  }
}

/** A failed command's error and, for an error reply of Redis, its prefix, the word before the first space. */
function failureDetail(error: unknown, ReplyError: new () => Error): Record<string, string> {
  return error instanceof ReplyError
    ? { error: errorName(error), code: error.message.split(" ")[0] }
    : { error: errorName(error) };
}

function instrumentSendCommand(original: SendCommand, identifier: RegExp, ReplyError: new () => Error): SendCommand {
  return function (this: unknown, command: Command, stream?: unknown) {
    const name = command.name.toUpperCase();
    const spec = TABLE.commands[name];
    if (command[HANDLED] || spec === undefined) {
      return original.call(this, command, stream);
    }
    command[HANDLED] = true;
    const key = keyOf(spec.key, command.args);
    const point = pointId(CORE.settings.service, spec.kind, key === null ? name : `${name} ${key.replace(identifier, "{}")}`);
    const rule = CORE.decide(point);
    const requestContext = context.active();
    const started = performance.now();
    command.promise.then((reply) => context.with(requestContext, () => CORE.observe(point,
      spec.empty === undefined ? "ok" : empty(spec.empty, reply) ? "empty" : "rows", performance.now() - started, rule, {})),
    (error: unknown) => context.with(requestContext, () => CORE.observe(point, "error", performance.now() - started, rule,
      failureDetail(error, ReplyError))));
    switch (rule?.action.kind) {
      case "fail":
        command.reject(new Error("faultpoint: injected Redis failure"));
        return command.promise;
      case "empty":
        if (spec.empty === "never") {
          CORE.abort(`rule ${rule.id}: ${name} has no empty reply`);
        }
        command.resolve(emptyReply(name, spec.empty, command.args));
        return command.promise;
      case "drop":
        command.resolve("OK");
        return command.promise;
      case "delay":
        setTimeout(() => original.call(this, command, stream), numberParameter(rule, "ms"));
        return command.promise;
      case "crash":
        return CORE.crash(typeof rule.action.code === "number" ? rule.action.code : 1);
      case "fail_after":
      case "duplicate":
        return CORE.abort(`rule ${rule.id}: ${rule.action.kind} at ${point} cannot resend an ioredis command`);
    }
    return original.call(this, command, stream);
  };
}

export const ioredisPlugin: Plugin = {
  name: "ioredis",
  install(core, options) {
    const ioredis = applicationModule<{
      Redis: { prototype: { sendCommand: SendCommand } }; Cluster?: { prototype: { sendCommand: SendCommand } }; ReplyError: new () => Error;
    }>(core.settings.sourceRoot, "ioredis");
    if (ioredis === null) {
      return;
    }
    const identifier = new RegExp(IoredisOptions.parse(options).key_identifier, "g");
    core.declare({
      store_read: ["fail", "empty", "delay", "crash"],
      store_write: ["fail", "drop", "delay", "crash"],
      publish: ["fail", "drop", "delay", "crash"],
      consume: ["fail", "empty", "delay", "crash"],
    });
    for (const client of [ioredis.Redis, ioredis.Cluster]) {
      if (client !== undefined) {
        client.prototype.sendCommand = instrumentSendCommand(client.prototype.sendCommand, identifier, ioredis.ReplyError);
      }
    }
  },
};
