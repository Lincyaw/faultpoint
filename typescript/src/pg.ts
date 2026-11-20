import { createHash } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";

import { context } from "@opentelemetry/api";
import { fingerprintSync, hasSqlDetails, loadModule, parseSync } from "libpg-query";

import { applicationModule } from "./config.js";
import { CORE, type Plugin } from "./core.js";
import { type Rule, numberParameter, pointId } from "./rules.js";

type StoreKind = "store_read" | "store_write";

interface Statement {
  kind: StoreKind;
  locator: string;
}

interface QueryResult {
  rows: unknown[];
  rowCount: number | null;
  command?: string;
  fields?: unknown[];
}

type Query = (this: unknown, ...arguments_: unknown[]) => unknown;

const STATEMENTS = new Map<string, Statement>();

/** The tables of a parse tree: every range variable, which is the node that carries a relname. */
function relations(tree: unknown, found: Set<string>): Set<string> {
  if (Array.isArray(tree)) {
    tree.forEach((item) => relations(item, found));
  } else if (tree !== null && typeof tree === "object") {
    const relname = (tree as { relname?: unknown }).relname;
    if (typeof relname === "string") {
      found.add(relname);
    }
    Object.values(tree).forEach((value) => relations(value, found));
  }
  return found;
}

/** The kind and locator of a statement, by PostgreSQL's own parser: a query is read and anything else written,
 * the tables it touches and its fingerprint, which ignores literals. Text PostgreSQL cannot parse is written,
 * since the server rejects it as no query. */
export function statementPoint(sql: string): Statement {
  const known = STATEMENTS.get(sql);
  if (known !== undefined) {
    return known;
  }
  let statement: Statement;
  try {
    const tree = parseSync(sql);
    const parsed = tree.stmts ?? [];
    const reads = parsed.length > 0 && parsed.every((entry) => entry.stmt !== undefined && "SelectStmt" in entry.stmt);
    const tables = [...relations(tree, new Set())].sort();
    statement = { kind: reads ? "store_read" : "store_write", locator: `${tables.join("+") || "-"}#${fingerprintSync(sql).slice(0, 8)}` };
  } catch (error) {
    if (!hasSqlDetails(error)) {
      throw error;
    }
    statement = { kind: "store_write", locator: `-#${createHash("sha256").update(sql).digest("hex").slice(0, 8)}` };
  }
  STATEMENTS.set(sql, statement);
  return statement;
}

function injectedError(message: string): Error {
  return Object.assign(new Error(`faultpoint: ${message}`), { code: "08006" });
}

function results(result: unknown): QueryResult[] {
  return (Array.isArray(result) ? result : [result]) as QueryResult[];
}

/** Run a query under its rule; a dropped write is acknowledged without reaching the database. */
async function execute(rule: Rule | null, run: () => Promise<unknown>): Promise<unknown> {
  switch (rule?.action.kind) {
    case "delay":
      await sleep(numberParameter(rule, "ms"));
      return run();
    case "crash":
      return CORE.crash(typeof rule.action.code === "number" ? rule.action.code : 1);
    case "fail":
      throw injectedError("injected store failure");
    case "drop":
      return { command: "", rowCount: 1, rows: [], fields: [] } satisfies QueryResult;
    case "duplicate":
      await run();
      return run();
    case "fail_after":
      await run();
      throw injectedError("store failed after the statement ran");
    case "empty": {
      const result = await run();
      results(result).forEach((each) => Object.assign(each, { rows: [], rowCount: 0 }));
      return result;
    }
  }
  return run();
}

/** Client.prototype.query, which Pool.query also goes through, made the store point of each statement; the
 * promise and callback forms both keep their contract. */
function instrumentQuery(original: Query): Query {
  return function (this: unknown, ...arguments_: unknown[]) {
    const [config, values, callback] = arguments_;
    const submittable = config !== null && typeof config === "object" && typeof (config as { submit?: unknown }).submit === "function";
    const text = typeof config === "string" ? config : (config as { text?: unknown } | null)?.text;
    if (submittable || typeof text !== "string") {
      return original.apply(this, arguments_);
    }
    const done = typeof values === "function" ? values : typeof callback === "function" ? callback : undefined;
    const forwarded = typeof values === "function" ? [config] : [config, values];
    const statement = statementPoint(text);
    const point = pointId(CORE.settings.service, statement.kind, statement.locator);
    const rule = CORE.decide(point);
    const requestContext = context.active();
    const started = performance.now();
    const observe = (outcome: string, quantity: number): void => context.with(requestContext,
      () => CORE.observe(point, outcome, quantity, rule));
    const result = execute(rule, () => original.apply(this, forwarded) as Promise<unknown>).then((answer) => {
      const each = results(answer);
      if (statement.kind === "store_read") {
        const rows = each.reduce((total, part) => total + (part?.rows?.length ?? 0), 0);
        observe(rows > 0 ? "rows" : "empty", rows);
      } else {
        observe("ok", each.reduce((total, part) => total + (part?.rowCount ?? 0), 0));
      }
      return answer;
    }, (error: unknown) => {
      observe("error", performance.now() - started);
      throw error;
    });
    if (done === undefined) {
      return result;
    }
    result.then((answer) => (done as (error: unknown, answer?: unknown) => void)(null, answer),
      (error) => (done as (error: unknown) => void)(error));
    return undefined;
  };
}

export const pgPlugin: Plugin = {
  name: "pg",
  async install(core) {
    const pg = applicationModule<{ Client: { prototype: { query: Query } } }>(core.settings.sourceRoot, "pg");
    if (pg === null) {
      return;
    }
    await loadModule();
    core.declare({
      store_read: ["fail", "empty", "delay", "crash"],
      store_write: ["fail", "fail_after", "drop", "duplicate", "delay", "crash"],
    });
    pg.Client.prototype.query = instrumentQuery(pg.Client.prototype.query);
  },
};
