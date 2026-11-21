import { POINTS_SYMBOL } from "./config.js";
import { CORE, type Plugin } from "./core.js";
import { type Rule, numberParameter } from "./rules.js";

/** Perform delay and crash, blocking the thread as contention does. */
function hold(rule: Rule): void {
  if (rule.action.kind === "delay") {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, numberParameter(rule, "ms"));
  }
  if (rule.action.kind === "crash") {
    CORE.crash(typeof rule.action.code === "number" ? rule.action.code : 1);
  }
}

/** Whether a guarded error path runs: its natural condition, or forced by a fail rule. */
export function branch(point: string, taken: boolean): boolean {
  if (!CORE.enabled) {
    return taken;
  }
  const rule = CORE.decide(point);
  if (rule !== null) {
    hold(rule);
    taken = taken || rule.action.kind === "fail";
  }
  CORE.observe(point, taken ? "taken" : "not_taken", 0, rule, {});
  return taken;
}

/** The result of a detector, negated by a negate rule. */
export function check(point: string, result: boolean): boolean {
  if (!CORE.enabled) {
    return result;
  }
  const rule = CORE.decide(point);
  if (rule !== null) {
    hold(rule);
    result = result !== (rule.action.kind === "negate");
  }
  CORE.observe(point, result ? "true" : "false", 0, rule, {});
  return result;
}

/** One iteration of a loop, delayed by a delay rule to model contention. */
export function loop(point: string): void {
  if (!CORE.enabled) {
    return;
  }
  const rule = CORE.decide(point);
  if (rule !== null) {
    hold(rule);
  }
  CORE.observe(point, "iteration", 0, rule, {});
}

/** A business value, replaced by a set rule or offset by a shift rule. */
export function value<T>(point: string, observed: T): T {
  if (!CORE.enabled) {
    return observed;
  }
  const rule = CORE.decide(point);
  let result = observed;
  if (rule !== null) {
    hold(rule);
    if (rule.action.kind === "set") {
      result = rule.action.value as T;
    }
    if (rule.action.kind === "shift") {
      if (typeof observed !== "number") {
        CORE.abort(`rule ${rule.id} shifts a non-numeric value at ${point}`);
      }
      result = ((observed as number) + numberParameter(rule, "amount")) as T;
    }
  }
  CORE.observe(point, "observed", typeof result === "number" ? result : 0, rule, {});
  return result;
}

/** A clock reading, epoch milliseconds or a Date, moved by a shift rule's seconds. */
export function clock<T extends number | Date>(point: string, reading: T): T {
  if (!CORE.enabled) {
    return reading;
  }
  const rule = CORE.decide(point);
  let result = reading;
  if (rule !== null) {
    hold(rule);
    if (rule.action.kind === "shift") {
      const shift = numberParameter(rule, "amount") * 1000;
      result = (reading instanceof Date ? new Date(reading.getTime() + shift) : (reading as number) + shift) as T;
    }
  }
  CORE.observe(point, "read", 0, rule, {});
  return result;
}

/** Whether a resource was acquired: its natural outcome, or rejected by a fail rule. */
export function acquire(point: string, acquired: boolean): boolean {
  if (!CORE.enabled) {
    return acquired;
  }
  const rule = CORE.decide(point);
  if (rule !== null) {
    hold(rule);
    acquired = acquired && rule.action.kind !== "fail";
  }
  CORE.observe(point, acquired ? "acquired" : "rejected", 0, rule, {});
  return acquired;
}

export const pointsPlugin: Plugin = {
  name: "points",
  install(core) {
    core.declare({
      branch: ["fail", "delay", "crash"],
      check: ["negate", "delay", "crash"],
      loop: ["delay", "crash"],
      value: ["set", "shift", "delay", "crash"],
      clock: ["shift", "delay", "crash"],
      acquire: ["fail", "delay", "crash"],
    });
    (globalThis as Record<symbol, unknown>)[Symbol.for(POINTS_SYMBOL)] = { branch, check, loop, value, clock, acquire };
  },
};
