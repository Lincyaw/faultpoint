import { readFileSync } from "node:fs";

import { context } from "@opentelemetry/api";
import { z } from "zod";

import { applicationModule } from "./config.js";
import { CORE, type Plugin, errorName } from "./core.js";
import { type Rule, numberParameter, pointId, pointParts, stringParameter } from "./rules.js";

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
  /** Arm ioredis's command timeout, which rejects the command with its own error unless an earlier timer is armed. */
  setTimeout(ms: number): void;
  [HANDLED]?: boolean;
}

/** The client's command timeout, which ends a wait as it ends a slow reply, with ioredis's own error: armed from the
 * start of the wait, it counts the wait as the reply's latency; cut runs when it ends the wait first. */
function truncate(client: unknown, command: Command, cut: () => void): void {
  const timeout = (client as { options?: { commandTimeout?: unknown } }).options?.commandTimeout;
  if (typeof timeout === "number") {
    command.setTimeout(timeout);
    command.promise.catch(cut);
  }
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

/** ioredis's error for an error reply of Redis, whose message is the reply. */
type ReplyError = new (message: string) => Error;

/** The prefix of an error reply, which Redis writes as an upper-case word. */
const REPLY_CODE = /^[A-Z][A-Z0-9_]*$/;

/** A failed command's error and, for an error reply of Redis, its prefix, the word before the first space. */
function failureDetail(error: unknown, ReplyError: ReplyError): Record<string, string> {
  return error instanceof ReplyError
    ? { error: errorName(error), code: error.message.split(" ")[0] }
    : { error: errorName(error) };
}

/** Whether a locator has the shape the adapter makes: its first word is a command of the table. */
function commandLocator(locator: string): boolean {
  return TABLE.commands[locator.split(" ")[0]] !== undefined;
}

/** Why a rule at a Redis point cannot be obeyed: a code that is not an upper-case word, which is not the prefix of an
 * error reply. */
function refusal(rule: Rule): string | null {
  const { kind, locator } = pointParts(rule.point);
  const code = stringParameter(rule, "code");
  const spec = TABLE.commands[locator.split(" ")[0]];
  return code === undefined || spec === undefined || spec.kind !== kind || REPLY_CODE.test(code) ? null
    : `code ${code} at ${rule.point} is not the prefix of a Redis error reply, an upper-case word`;
}

function instrumentSendCommand(original: SendCommand, identifier: RegExp, ReplyError: ReplyError): SendCommand {
  return function (this: unknown, command: Command, stream?: unknown) {
    const name = command.name.toUpperCase();
    const spec = TABLE.commands[name];
    if (command[HANDLED] || spec === undefined) {
      return original.call(this, command, stream);
    }
    command[HANDLED] = true;
    // The client sends the command and its errors reach the application; whether and how it is answered instead is
    // faultpoint's own work, as is observing the reply.
    const answered = CORE.own(() => {
      const key = keyOf(spec.key, command.args);
      const point = pointId(CORE.settings.service, spec.kind, key === null ? name : `${name} ${key.replace(identifier, "{}")}`);
      const rule = CORE.decide(point);
      const requestContext = context.active();
      const started = performance.now();
      // The total of a command, like its elapsed time, is the milliseconds until its reply.
      const observe = (outcome: string, detail: Record<string, string>): void => context.with(requestContext, () => {
        const elapsed = performance.now() - started;
        CORE.observe(point, outcome, elapsed, elapsed, rule, detail);
      });
      // A delayed command is always sent, when its delay passes or when the command timeout cuts it, and a failed one never.
      const sent: Record<string, string> = rule?.action.kind === "delay" ? { sent: "true" } : rule?.action.kind === "fail" ? { sent: "false" } : {};
      command.promise.then((reply) => CORE.own(() => observe(spec.empty === undefined ? "ok" : empty(spec.empty, reply) ? "empty" : "rows", {})),
        (error: unknown) => CORE.own(() => observe("error", { ...failureDetail(error, ReplyError), ...sent })));
      switch (rule?.action.kind) {
        case "fail": {
          // With a code the error is the one ioredis makes for that error reply, which carries the command.
          const code = stringParameter(rule, "code");
          const failure = code === undefined ? new Error("faultpoint: injected Redis failure")
            : Object.assign(new ReplyError(`${code} faultpoint: injected Redis failure`), { command: { name: command.name, args: command.args } });
          // A fail with ms waits as a delay does, before it fails; cut short by the command timeout, it sends nothing.
          if (rule.action.ms === undefined) {
            command.reject(failure);
          } else {
            const failing = setTimeout(() => command.reject(failure), numberParameter(rule, "ms"));
            truncate(this, command, () => clearTimeout(failing));
          }
          return true;
        }
        case "empty":
          if (spec.empty === "never") {
            CORE.abort(`rule ${rule.id}: ${name} has no empty reply`);
          }
          command.resolve(emptyReply(name, spec.empty, command.args));
          return true;
        case "drop":
          command.resolve("OK");
          return true;
        case "delay": {
          // A delay stands for a slow server, which has the command already and runs it: cut short by the command
          // timeout, the command is sent at once and its reply, which the rejected command no longer takes, dropped.
          let sent = false;
          const send = (): void => {
            sent = true;
            original.call(this, command, stream);
          };
          const sending = setTimeout(send, numberParameter(rule, "ms"));
          truncate(this, command, () => {
            if (!sent) {
              clearTimeout(sending);
              send();
            }
          });
          return true;
        }
        case "crash":
          return CORE.crash(typeof rule.action.code === "number" ? rule.action.code : 1);
        case "fail_after":
        case "duplicate":
          return CORE.abort(`rule ${rule.id}: ${rule.action.kind} at ${point} cannot resend an ioredis command`);
      }
      return false;
    });
    return answered ? command.promise : original.call(this, command, stream);
  };
}

export const ioredisPlugin: Plugin = {
  name: "ioredis",
  install(core, options) {
    const ioredis = applicationModule<{
      Redis: { prototype: { sendCommand: SendCommand } }; Cluster?: { prototype: { sendCommand: SendCommand } }; ReplyError: ReplyError;
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
    }, commandLocator);
    core.check(refusal);
    for (const client of [ioredis.Redis, ioredis.Cluster]) {
      if (client !== undefined) {
        client.prototype.sendCommand = instrumentSendCommand(client.prototype.sendCommand, identifier, ioredis.ReplyError);
      }
    }
  },
};
