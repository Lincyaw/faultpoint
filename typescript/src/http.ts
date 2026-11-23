import { AsyncLocalStorage } from "node:async_hooks";
import diagnostics from "node:diagnostics_channel";
import http, { type ClientRequest, IncomingMessage, type ServerResponse } from "node:http";
import https from "node:https";
import { syncBuiltinESMExports } from "node:module";
import { Socket } from "node:net";

import { ROOT_CONTEXT, context, defaultTextMapGetter, defaultTextMapSetter } from "@opentelemetry/api";
import { z } from "zod";

import { PROPAGATOR } from "./context.js";
import { ACTS_AFTER, ACTS_BEFORE, CORE, EVERY_LOCATOR, type Plugin, errorName } from "./core.js";
import { type Rule, numberParameter, pointId, pointParts, stringParameter } from "./rules.js";

const DEFAULT_FAILURE_STATUS = 503;

/** The fetch exchange in progress, and the exchange of each request undici creates for it; undici creates a request
 * in the context of the fetch that sends it, and announces it sent once its headers and body are written. */
const EXCHANGES = new AsyncLocalStorage<{ sent: boolean }>();
/** A signal nothing aborts, for a wait that runs to its end. */
const STAYING = new AbortController().signal;
const REQUEST_EXCHANGES = new WeakMap<object, { sent: boolean }>();

export const HttpOptions = z.strictObject({
  identifier_segment: z.string().default(
    "^(\\d+|([A-Za-z][A-Za-z0-9_]*-)?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|([A-Za-z][A-Za-z0-9_]*[_-])?[0-9a-fA-F]{16,})$"),
});

type Handler = (request: IncomingMessage, response: ServerResponse) => unknown;

/** Node's HTTP boundaries: the server's request event, fetch and http.request. */
class HttpBoundaries {
  readonly identifierSegment: RegExp;

  constructor(options: z.infer<typeof HttpOptions>) {
    this.identifierSegment = new RegExp(options.identifier_segment);
  }

  /** A request path with identifier segments replaced, so that one route is one point. */
  pathTemplate(path: string): string {
    return path.split("?")[0].split("/").map((segment) => (this.identifierSegment.test(segment) ? "{}" : segment)).join("/");
  }

  /** The rpc_server point of a handler, which also restores the caller's trace context and baggage. */
  serverHandler(handler: Handler): Handler {
    return (request, response) => context.with(
      CORE.own(() => PROPAGATOR.extract(ROOT_CONTEXT, request.headers, defaultTextMapGetter)), () => this.serve(handler, request, response));
  }

  /** The handler is the application's; everything around it is faultpoint's own work. */
  async serve(handler: Handler, request: IncomingMessage, response: ServerResponse): Promise<void> {
    const requestContext = context.active();
    const started = performance.now();
    let observed: Rule | null = null;
    const rule = CORE.own(() => {
      const point = pointId(CORE.settings.service, "rpc_server", `${request.method} ${this.pathTemplate(request.url ?? "/")}`);
      const decided = CORE.decideAmong(point, ACTS_BEFORE);
      observed = decided;
      // A response that closes before it finished was abandoned: its connection closed first.
      response.on("close", () => CORE.own(() => context.with(requestContext, () => observeExchange(point,
        response.writableFinished ? statusOutcome(response.statusCode) : "error", started, observed,
        response.writableFinished ? { status: String(response.statusCode), abandoned: "false" } : { abandoned: "true" }))));
      if (decided?.action.kind !== "fail") {
        answerOnceWritten(response, () => context.with(requestContext, () => CORE.decideAmong(point, ACTS_AFTER)), (replacing) => {
          observed = replacing;
        });
      }
      return decided;
    });
    // A server's wait runs to its end whoever leaves, as a slow server goes on for a client gone.
    if (rule !== null) {
      await wait(rule, STAYING);
    }
    if (rule?.action.kind === "fail") {
      CORE.own(() => response.writeHead(failureStatus(rule)).end());
      return;
    }
    await handler(request, response);
  }

  /** A fetch whose requests are rpc_client points and carry the current trace context and baggage; the application's
   * input and the base fetch fail as they would without faultpoint, around faultpoint's own work. */
  instrumentFetch(base: typeof fetch): typeof fetch {
    return async (input, init) => {
      const request = new Request(input, init);
      const { point, rule } = CORE.own(() => {
        const carrier: Record<string, string> = {};
        PROPAGATOR.inject(context.active(), carrier, defaultTextMapSetter);
        for (const [name, value] of Object.entries(carrier)) {
          request.headers.set(name, value);
        }
        const url = new URL(request.url);
        const id = pointId(CORE.settings.service, "rpc_client", `${request.method} ${url.host}${this.pathTemplate(url.pathname)}`);
        return { point: id, rule: CORE.decideAmong(id, ACTS_BEFORE) };
      });
      const kind = rule?.action.kind;
      const started = performance.now();
      if (rule !== null) {
        await wait(rule, request.signal);
      }
      // A caller that gave up during the wait gets what fetch rejects with when it is aborted. A delay stands for a slow
      // peer, which has the request already and runs it, so the request is sent all the same and its answer dropped; a
      // fail with ms sends nothing.
      if (rule !== null && request.signal.aborted) {
        const reason: unknown = request.signal.reason;
        const sent = kind === "delay";
        if (sent) {
          base(new Request(request, { signal: null })).then((dropped) => dropped.body?.cancel(), () => undefined);
        }
        CORE.own(() => observeExchange(point, errorOutcome(reason), started, rule, { error: errorName(reason), sent: String(sent) }));
        throw reason;
      }
      if (rule !== null && kind === "fail") {
        return failFetch(point, rule, started);
      }
      let response: Response;
      const exchange = { sent: false };
      try {
        if (kind === "duplicate") {
          await (await base(request.clone())).arrayBuffer();
        }
        response = await EXCHANGES.run(exchange, () => base(request));
      } catch (error) {
        CORE.own(() => observeExchange(point, errorOutcome(error), started, rule,
          { error: errorName(error), sent: String(exchange.sent) }));
        throw error;
      }
      // Only a request answered with 2xx or 3xx is one a fail_after rule replaces and counts.
      const replacing = CORE.own(() => (succeeded(response.status) ? CORE.decideAmong(point, ACTS_AFTER) : null));
      if (replacing !== null) {
        await response.arrayBuffer();
        return failFetch(point, replacing, started);
      }
      CORE.own(() => observeExchange(point, statusOutcome(response.status), started, rule, { status: String(response.status) }));
      return response;
    };
  }

  /** An http.request whose requests are rpc_client points and carry the current trace context and baggage; the original
   * request fails as it would without faultpoint, and what follows is faultpoint's own work. */
  instrumentRequest(original: typeof http.request): typeof http.request {
    const boundaries = this;
    return function (this: unknown, ...arguments_: Parameters<typeof http.request>) {
      const clientRequest = original.apply(this, arguments_);
      return CORE.own(() => {
        const carrier: Record<string, string> = {};
        PROPAGATOR.inject(context.active(), carrier, defaultTextMapSetter);
        for (const [name, value] of Object.entries(carrier)) {
          clientRequest.setHeader(name, value);
        }
        const host = String(clientRequest.getHeader("host") ?? clientRequest.host);
        const point = pointId(CORE.settings.service, "rpc_client",
          `${clientRequest.method} ${host}${boundaries.pathTemplate(clientRequest.path)}`);
        const rule = CORE.decideAmong(point, ACTS_BEFORE);
        const requestContext = context.active();
        const started = performance.now();
        const observe = (outcome: string, detail: Record<string, string>, observed: Rule | null): void => CORE.own(
          () => context.with(requestContext, () => observeExchange(point, outcome, started, observed, detail)));
        if (rule?.action.kind === "duplicate") {
          CORE.abort(`rule ${rule.id}: duplicate at ${point} needs fetch, since an http.request body cannot be sent twice`);
        }
        if (rule?.action.kind === "crash") {
          CORE.crash(typeof rule.action.code === "number" ? rule.action.code : 1);
        }
        if (rule?.action.kind === "fail") {
          answerInstead(clientRequest, rule, observe);
          return clientRequest;
        }
        // A request finishes when its headers and body have been handed to the operating system.
        const exchange = { sent: false, replaced: false };
        if (rule?.action.kind === "delay") {
          // The same request again, without the caller's callback, signal or timeout, as no one takes its answer.
          const resend = (): ClientRequest => original.apply(this, arguments_.filter((argument) => typeof argument !== "function")
            .map((argument) => (argument !== null && typeof argument === "object" && !(argument instanceof URL)
              ? { ...argument, signal: undefined, timeout: undefined } : argument)) as Parameters<typeof http.request>);
          deferSending(clientRequest, numberParameter(rule, "ms"), exchange, resend);
        }
        clientRequest.once("finish", () => {
          exchange.sent = true;
        });
        receiveResponse(clientRequest, rule, exchange, () => context.with(requestContext, () => CORE.decideAmong(point, ACTS_AFTER)), observe);
        clientRequest.once("error", (error) => {
          if (!exchange.replaced) {
            observe(errorOutcome(error), { error: errorName(error), sent: String(exchange.sent) }, rule);
          }
        });
        return clientRequest;
      });
    } as typeof http.request;
  }
}

function statusOutcome(status: number): string {
  return `${Math.floor(status / 100)}xx`;
}

/** Observe an exchange, whose total, like its elapsed time, is the milliseconds since it started. */
function observeExchange(point: string, outcome: string, started: number, rule: Rule | null, detail: Record<string, string>): void {
  const elapsed = performance.now() - started;
  CORE.observe(point, outcome, elapsed, elapsed, rule, detail);
}

/** Whether a rule waits ms before it acts: a delay, and a fail that fails slowly. */
function waits(rule: Rule): boolean {
  return rule.action.kind === "delay" || (rule.action.kind === "fail" && rule.action.ms !== undefined);
}

/** Delay without blocking other requests, since a boundary delay models a slow peer; a fail with ms waits the same way.
 * The wait ends early when the signal aborts, as a slow peer's does for a caller that gives up or a client that leaves. */
function wait(rule: Rule, signal: AbortSignal): Promise<void> {
  return CORE.own(() => {
    if (rule.action.kind === "crash") {
      CORE.crash(typeof rule.action.code === "number" ? rule.action.code : 1);
    }
    if (!waits(rule) || signal.aborted) {
      return Promise.resolve();
    }
    const ms = numberParameter(rule, "ms");
    return new Promise<void>((resolve) => {
      const ended = (): void => {
        clearTimeout(timer);
        signal.removeEventListener("abort", ended);
        resolve();
      };
      const timer = setTimeout(ended, ms);
      signal.addEventListener("abort", ended, { once: true });
    });
  });
}

function failureStatus(rule: Rule): number {
  return typeof rule.action.status === "number" ? rule.action.status : DEFAULT_FAILURE_STATUS;
}

/** Replace a response's writers with ones that discard until the handler ends it, then send a failure. */
/** Whether an answer is the success of an exchange, 2xx or 3xx, which is the only one fail_after replaces. */
function succeeded(status: number): boolean {
  return status >= 200 && status < 400;
}

/** Watch a response as its handler starts to write it. At the first writer call the status is known, and a fail_after
 * rule decided then, which only a 2xx or 3xx answer counts, answers with the rule's failure instead, dropping the
 * handler's headers and body; otherwise the writers are put back and the call goes on. */
function answerOnceWritten(response: ServerResponse, decide: () => Rule | null, replaced: (rule: Rule) => void): void {
  const { writeHead, write, end } = response;
  const restore = (): void => {
    Object.assign(response, { writeHead, write, end });
  };
  const replaces = (status: number): boolean => {
    restore();
    const replacement = succeeded(status) ? decide() : null;
    if (replacement === null) {
      return false;
    }
    replaced(replacement);
    response.writeHead = (() => response) as typeof response.writeHead;
    response.write = (() => true) as typeof response.write;
    response.end = (() => CORE.own(() => {
      restore();
      for (const name of response.getHeaderNames()) {
        response.removeHeader(name);
      }
      response.writeHead(failureStatus(replacement)).end();
      return response;
    })) as typeof response.end;
    return true;
  };
  // The writers are the handler's, whose errors are its own; deciding the answer is faultpoint's own work.
  response.writeHead = ((status: number, ...rest: unknown[]) => (CORE.own(() => replaces(status)) ? response
    : writeHead.apply(response, [status, ...rest] as Parameters<typeof writeHead>))) as typeof response.writeHead;
  response.write = ((...rest: unknown[]) => (CORE.own(() => replaces(response.statusCode)) ? true
    : write.apply(response, rest as Parameters<typeof write>))) as typeof response.write;
  response.end = ((...rest: unknown[]) => (CORE.own(() => replaces(response.statusCode)) ? response.end()
    : end.apply(response, rest as Parameters<typeof end>))) as typeof response.end;
}

function boundaryError(rule: Rule): Error {
  const code = stringParameter(rule, "error") === "refused" ? "ECONNREFUSED" : "ETIMEDOUT";
  return Object.assign(new Error(`faultpoint: ${code}`), { code });
}

/** The failure a fail or fail_after rule answers a fetch with; only a fail_after has sent the request. */
function failFetch(point: string, rule: Rule, started: number): Response {
  const answer = CORE.own((): Response | Error => {
    const sent = String(rule.action.kind === "fail_after");
    if (typeof rule.action.status === "number") {
      observeExchange(point, statusOutcome(rule.action.status), started, rule, { status: String(rule.action.status), sent });
      return new Response(null, { status: rule.action.status });
    }
    const error = stringParameter(rule, "error") === "refused"
      ? new TypeError("fetch failed", { cause: boundaryError(rule) })
      : new DOMException("The operation was aborted due to timeout", "TimeoutError");
    observeExchange(point, errorOutcome(error), started, rule, { error: errorName(error), sent });
    return error;
  });
  if (answer instanceof Response) {
    return answer;
  }
  throw answer;
}

function errorOutcome(error: unknown): string {
  if (error instanceof Error && error.name === "TimeoutError") {
    return "timeout";
  }
  const code = error instanceof Error
    ? ((error as { code?: string }).code ?? (error.cause as { code?: string } | undefined)?.code)
    : undefined;
  if (code === "ETIMEDOUT" || code === "ESOCKETTIMEDOUT") {
    return "timeout";
  }
  return code === "ECONNREFUSED" ? "refused" : "error";
}

function syntheticResponse(status: number): IncomingMessage {
  const response = new IncomingMessage(new Socket());
  response.statusCode = status;
  response.push(null);
  return response;
}

/** Hold back what the caller writes until the delay passes, so that the request leaves late. A caller that gives up
 * during the delay destroys the request, its timeout's or its abort's error reaching it as from a slow peer; a delay
 * stands for a slow peer, which has the request already and runs it, so a request the caller had ended is sent again
 * with the same headers and body by resend, and its answer dropped. */
function deferSending(clientRequest: ClientRequest, ms: number, exchange: { sent: boolean }, resend: () => ClientRequest): void {
  type Writer = (this: ClientRequest, ...arguments_: unknown[]) => unknown;
  const { write, end } = clientRequest;
  const pending: Array<{ ends: boolean; arguments_: unknown[] }> = [];
  let ready = false;
  const timer = setTimeout(() => {
    ready = true;
    Object.assign(clientRequest, { write, end });
    pending.forEach((each) => ((each.ends ? end : write) as Writer).apply(clientRequest, each.arguments_));
  }, ms);
  const truncated = (): void => CORE.own(() => {
    if (ready) {
      return;
    }
    ready = true;
    clearTimeout(timer);
    if (!pending.some((each) => each.ends)) {
      return;
    }
    exchange.sent = true;
    const again = resend();
    for (const [name, value] of Object.entries(clientRequest.getHeaders())) {
      if (value !== undefined) {
        again.setHeader(name, value);
      }
    }
    again.on("response", (dropped) => dropped.resume());
    again.on("error", () => undefined);
    // The caller's write callbacks belong to the request it gave up.
    for (const each of pending) {
      ((each.ends ? again.end : again.write) as Writer).apply(again, each.arguments_.filter((argument) => typeof argument !== "function"));
    }
  });
  clientRequest.once("error", truncated);
  clientRequest.once("close", truncated);
  clientRequest.write = ((...arguments_: Parameters<typeof write>) => {
    if (ready) {
      return write.apply(clientRequest, arguments_);
    }
    pending.push({ ends: false, arguments_ });
    return true;
  }) as typeof write;
  clientRequest.end = ((...arguments_: Parameters<typeof end>) => {
    if (ready) {
      return end.apply(clientRequest, arguments_);
    }
    pending.push({ ends: true, arguments_ });
    return clientRequest;
  }) as typeof end;
}

/** Answer a request without sending it: a synthetic status, or an error as if the peer failed. */
function answerInstead(clientRequest: ClientRequest, rule: Rule,
                       observe: (outcome: string, detail: Record<string, string>, observed: Rule | null) => void): void {
  clientRequest.write = (() => true) as typeof clientRequest.write;
  clientRequest.end = (() => clientRequest) as typeof clientRequest.end;
  // The response event runs the application's listeners, whose errors are their own.
  let answered = false;
  const answering = (): void => {
    answered = true;
    const answer = CORE.own((): IncomingMessage | Error => {
      if (typeof rule.action.status === "number") {
        observe(statusOutcome(rule.action.status), { status: String(rule.action.status), sent: "false" }, rule);
        return syntheticResponse(rule.action.status);
      }
      const error = boundaryError(rule);
      observe(errorOutcome(error), { error: errorName(error), sent: "false" }, rule);
      return error;
    });
    if (answer instanceof IncomingMessage) {
      clientRequest.emit("response", answer);
      clientRequest.destroy();
      return;
    }
    clientRequest.destroy(answer);
  };
  // A fail with ms answers once it has waited, on a timer as a delay sends late; a caller that gives up during the
  // wait destroys the request, and meets the request's own error, which is observed in place of the answer.
  if (waits(rule)) {
    const timer = setTimeout(answering, numberParameter(rule, "ms"));
    clientRequest.once("close", () => clearTimeout(timer));
    clientRequest.once("error", (error) => {
      if (!answered) {
        observe(errorOutcome(error), { error: errorName(error), sent: "false" }, rule);
      }
    });
  } else {
    process.nextTick(answering);
  }
}

/** Let a request reach its peer and watch its response: a fail_after rule decided when the response comes, which only
 * a 2xx or 3xx answer counts, hides it behind a failure; otherwise the response is observed and passed on. */
function receiveResponse(clientRequest: ClientRequest, rule: Rule | null, exchange: { replaced: boolean },
                         replacing: () => Rule | null, observe: (outcome: string, detail: Record<string, string>, observed: Rule | null) => void): void {
  const emit = clientRequest.emit;
  clientRequest.emit = function (this: ClientRequest, event: string | symbol, ...arguments_: unknown[]): boolean {
    if (event !== "response") {
      return emit.call(this, event, ...arguments_);
    }
    // The response event runs the application's listeners, whose errors are their own.
    const response = arguments_[0] as IncomingMessage;
    const answer = CORE.own((): IncomingMessage | Error => {
      const replacement = succeeded(response.statusCode ?? 0) ? replacing() : null;
      if (replacement === null) {
        observe(statusOutcome(response.statusCode ?? 0), { status: String(response.statusCode ?? 0) }, rule);
        return response;
      }
      exchange.replaced = true;
      response.resume();
      if (typeof replacement.action.status === "number") {
        observe(statusOutcome(replacement.action.status), { status: String(replacement.action.status), sent: "true" }, replacement);
        return syntheticResponse(replacement.action.status);
      }
      const error = boundaryError(replacement);
      observe(errorOutcome(error), { error: errorName(error), sent: "true" }, replacement);
      return error;
    });
    if (answer instanceof IncomingMessage) {
      return emit.call(this, "response", answer, ...arguments_.slice(1));
    }
    this.destroy(answer);
    return true;
  } as typeof clientRequest.emit;
}

export const httpPlugin: Plugin = {
  name: "http",
  install(core, options) {
    const boundaries = new HttpBoundaries(HttpOptions.parse(options));
    core.declare({
      rpc_server: ["fail", "fail_after", "delay", "crash"],
      rpc_client: ["fail", "fail_after", "duplicate", "delay", "crash"],
    }, EVERY_LOCATOR);
    core.check((rule) => {
      const { kind, locator } = pointParts(rule.point);
      if ((kind === "rpc_client" || kind === "rpc_server") && !locator.startsWith("gRPC ")
        && (rule.action.kind === "fail" || rule.action.kind === "fail_after") && rule.action.code !== undefined) {
        return "HTTP failures require status, not a native RPC code";
      }
      return null;
    });
    for (const server of [http.Server.prototype, https.Server.prototype]) {
      const emit = server.emit as (this: http.Server, event: string | symbol, ...arguments_: unknown[]) => boolean;
      server.emit = function (this: http.Server, event: string | symbol, ...arguments_: unknown[]): boolean {
        if (event !== "request") {
          return emit.call(this, event, ...arguments_);
        }
        const [request, response] = arguments_ as [IncomingMessage, ServerResponse];
        boundaries.serverHandler((handled, answered) => emit.call(this, "request", handled, answered))(request, response);
        return true;
      } as typeof server.emit;
    }
    for (const module of [http, https]) {
      module.request = boundaries.instrumentRequest(module.request);
      module.get = function (...arguments_: Parameters<typeof http.get>) {
        const clientRequest = module.request(...(arguments_ as Parameters<typeof http.request>));
        clientRequest.end();
        return clientRequest;
      } as typeof http.get;
    }
    syncBuiltinESMExports();
    diagnostics.subscribe("undici:request:create", (message) => CORE.own(() => {
      const exchange = EXCHANGES.getStore();
      if (exchange !== undefined) {
        REQUEST_EXCHANGES.set((message as { request: object }).request, exchange);
      }
    }));
    diagnostics.subscribe("undici:request:bodySent", (message) => CORE.own(() => {
      const exchange = REQUEST_EXCHANGES.get((message as { request: object }).request);
      if (exchange !== undefined) {
        exchange.sent = true;
      }
    }));
    globalThis.fetch = boundaries.instrumentFetch(globalThis.fetch);
  },
};
