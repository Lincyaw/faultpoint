import { createHash } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";

import { context } from "@opentelemetry/api";
import { fingerprintSync, hasSqlDetails, loadModule, parseSync } from "libpg-query";

import { applicationModule } from "./config.js";
import { ACTS_AFTER, ACTS_BEFORE, CORE, type Plugin, errorName } from "./core.js";
import { type Rule, numberParameter, pointId, pointParts, stringParameter } from "./rules.js";

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

/** node-postgres's error for an error response of the server, whose code is the SQLSTATE. */
type DatabaseError = new (message: string, length: number, name: string) => Error & { code?: string };

const STATEMENTS = new Map<string, Statement>();
/** The locators statementPoint makes. */
const STATEMENT_LOCATOR = /^[^ ]+#[0-9a-f]{8}$/;
const SQLSTATE = /^[0-9A-Z]{5}$/;

/** The nodes that write wherever they sit in a parse tree, a WITH item included. */
const WRITES = ["InsertStmt", "UpdateStmt", "DeleteStmt", "MergeStmt"];

/** What a parse tree touches: the range variables, which are the nodes that carry a relname, with and without a
 * schema; the names of its WITH items; and whether a node of it writes, as a statement of WRITES or a query INTO a
 * table does. */
interface Touched {
  qualified: Set<string>;
  unqualified: Set<string>;
  named: Set<string>;
  writes: boolean;
}

function touched(tree: unknown, found: Touched): Touched {
  if (Array.isArray(tree)) {
    tree.forEach((item) => touched(item, found));
  } else if (tree !== null && typeof tree === "object") {
    const node = tree as { relname?: unknown; schemaname?: unknown; ctename?: unknown };
    if (typeof node.relname === "string") {
      (node.schemaname === undefined ? found.unqualified : found.qualified).add(node.relname);
    }
    if (typeof node.ctename === "string") {
      found.named.add(node.ctename);
    }
    found.writes ||= "intoClause" in node || WRITES.some((name) => name in node);
    Object.values(tree).forEach((value) => touched(value, found));
  }
  return found;
}

/** The kind and locator of a statement, by PostgreSQL's own parser: a query that writes through neither a WITH item
 * nor INTO is read and anything else written, the tables it touches, a table without a schema named as a WITH item
 * being that item, and its fingerprint, which ignores literals. Text PostgreSQL cannot parse is written, since the
 * server rejects it as no query. */
export function statementPoint(sql: string): Statement {
  const known = STATEMENTS.get(sql);
  if (known !== undefined) {
    return known;
  }
  let statement: Statement;
  try {
    const tree = parseSync(sql);
    const parsed = tree.stmts ?? [];
    const found = touched(tree, { qualified: new Set(), unqualified: new Set(), named: new Set(), writes: false });
    const reads = parsed.length > 0 && !found.writes && parsed.every((entry) => entry.stmt !== undefined && "SelectStmt" in entry.stmt);
    const tables = [...new Set([...found.qualified, ...[...found.unqualified].filter((name) => !found.named.has(name))])].sort();
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

function results(result: unknown): QueryResult[] {
  return (Array.isArray(result) ? result : [result]) as QueryResult[];
}

/** Whether a locator has the shape statementPoint makes, which is the points this plugin serves. */
function statementLocator(locator: string): boolean {
  return STATEMENT_LOCATOR.test(locator);
}

/** Why a rule at a statement point cannot be obeyed: a code that is not a SQLSTATE, which PostgreSQL never reports. */
function refusal(rule: Rule): string | null {
  const { kind, locator } = pointParts(rule.point);
  const code = stringParameter(rule, "code");
  return code === undefined || (kind !== "store_read" && kind !== "store_write") || !statementLocator(locator)
    || SQLSTATE.test(code) ? null : `code ${code} at ${rule.point} is not a SQLSTATE, five digits or upper-case letters`;
}

/** The error a fail or fail_after rule raises: an error response of the rule's SQLSTATE, or of 08006,
 * connection_failure, when it names none. */
function injectedError(DatabaseError: DatabaseError, rule: Rule, message: string): Error {
  return Object.assign(new DatabaseError(`faultpoint: ${message}`, 0, "error"),
    { severity: "ERROR", code: stringParameter(rule, "code") ?? "08006" });
}

/** A failed statement's error and, for an error response of PostgreSQL, its SQLSTATE. */
function failureDetail(error: unknown, DatabaseError: DatabaseError): Record<string, string> {
  return error instanceof DatabaseError && typeof error.code === "string"
    ? { error: errorName(error), code: error.code } : { error: errorName(error) };
}

/** Run a query under the rule decided before it; a dropped write is acknowledged without reaching the database. */
async function execute(rule: Rule | null, run: () => Promise<unknown>, DatabaseError: DatabaseError): Promise<unknown> {
  switch (rule?.action.kind) {
    case "delay":
      await sleep(numberParameter(rule, "ms"));
      return run();
    case "crash":
      return CORE.crash(typeof rule.action.code === "number" ? rule.action.code : 1);
    case "fail":
      throw injectedError(DatabaseError, rule, "injected store failure");
    case "drop":
      return { command: "", rowCount: 1, rows: [], fields: [] } satisfies QueryResult;
    case "duplicate":
      await run();
      return run();
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
function instrumentQuery(original: Query, DatabaseError: DatabaseError): Query {
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
    const rule = CORE.decideAmong(point, ACTS_BEFORE);
    const requestContext = context.active();
    const started = performance.now();
    const observe = (outcome: string, quantity: number, observed: Rule | null, detail: Record<string, string>): void =>
      context.with(requestContext, () => CORE.observe(point, outcome, quantity, observed, detail));
    const result = execute(rule, () => original.apply(this, forwarded) as Promise<unknown>, DatabaseError).then((answer) => {
      // Only a statement that ran and succeeded is one a fail_after rule replaces and counts.
      const replacing = rule?.action.kind === "drop" ? null : context.with(requestContext, () => CORE.decideAmong(point, ACTS_AFTER));
      if (replacing !== null) {
        const error = injectedError(DatabaseError, replacing, "store failed after the statement ran");
        observe("error", performance.now() - started, replacing, failureDetail(error, DatabaseError));
        throw error;
      }
      const each = results(answer);
      if (statement.kind === "store_read") {
        const rows = each.reduce((total, part) => total + (part?.rows?.length ?? 0), 0);
        observe(rows > 0 ? "rows" : "empty", rows, rule, {});
      } else {
        observe("ok", each.reduce((total, part) => total + (part?.rowCount ?? 0), 0), rule, {});
      }
      return answer;
    }, (error: unknown) => {
      observe("error", performance.now() - started, rule, failureDetail(error, DatabaseError));
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
    const pg = applicationModule<{ Client: { prototype: { query: Query } }; DatabaseError: DatabaseError }>(core.settings.sourceRoot, "pg");
    if (pg === null) {
      return;
    }
    await loadModule();
    core.declare({
      store_read: ["fail", "empty", "delay", "crash"],
      store_write: ["fail", "fail_after", "drop", "duplicate", "delay", "crash"],
    }, statementLocator);
    core.check(refusal);
    pg.Client.prototype.query = instrumentQuery(pg.Client.prototype.query, pg.DatabaseError);
  },
};
