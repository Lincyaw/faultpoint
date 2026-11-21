import { readFileSync, statSync } from "node:fs";

import { z } from "zod";

/** An action is a kind and free parameters, which the plugin that executes it interprets;
 * spec/kinds.json and `faultpoint check` validate them before a rule set is installed. */
export const Action = z.looseObject({ kind: z.string().min(1) });
export type Action = z.infer<typeof Action> & Record<string, unknown>;

const POINT_SHAPE = /^[^:]+:[^:]+:.+$/;

export function pointId(service: string, kind: string, locator: string): string {
  if (service.includes(":")) {
    throw new Error(`a service name cannot contain ':': ${service}`);
  }
  return `${service}:${kind}:${locator}`;
}

/** The service and kind of a point id, which is <service>:<kind>:<locator>. */
export function pointParts(point: string): { service: string; kind: string; locator: string } {
  const [service, kind, ...locator] = point.split(":");
  if (!service || !kind || locator.length === 0) {
    throw new Error(`a point id is <service>:<kind>:<locator>: ${point}`);
  }
  return { service, kind, locator: locator.join(":") };
}

export const Trigger = z.strictObject({
  skip: z.number().int().min(0).default(0),
  limit: z.number().int().min(1).nullable().default(null),
  probability: z.number().gt(0).max(1).default(1),
});

export const Rule = z.strictObject({
  id: z.string().min(1),
  point: z.string().regex(POINT_SHAPE, "a point id is <service>:<kind>:<locator>"),
  action: Action,
  scope: z.record(z.string(), z.string()).default({}),
  trigger: Trigger.default({ skip: 0, limit: null, probability: 1 }),
});
export type Rule = z.infer<typeof Rule>;

export const RuleSet = z.strictObject({
  experiment: z.string().min(1),
  rules: z.array(Rule).default([]),
}).refine((ruleset) => new Set(ruleset.rules.map((rule) => rule.id)).size === ruleset.rules.length,
  { message: "rule ids repeat" });
export type RuleSet = z.infer<typeof RuleSet>;

/** The default rule source: the rule set file named by FAULTPOINT_RULES, reloaded when it changes. */
export class FileRuleSource {
  modified: number | null = null;

  constructor(readonly path: string, readonly intervalMs: number, readonly fail: (reason: string) => never) {}

  start(apply: (ruleset: RuleSet) => void): void {
    const poll = (): void => {
      const modified = statSync(this.path).mtimeMs;
      if (modified !== this.modified) {
        apply(RuleSet.parse(JSON.parse(readFileSync(this.path, "utf-8"))));
        this.modified = modified;
      }
    };
    poll();
    setInterval(() => {
      try {
        poll();
      } catch (error) {
        this.fail(`unusable rules in ${this.path}: ${String(error)}`);
      }
    }, this.intervalMs).unref();
  }
}

/** A numeric parameter of an action, which the executing plugin requires. */
export function numberParameter(rule: Rule, name: string): number {
  const value = rule.action[name];
  if (typeof value !== "number") {
    throw new Error(`rule ${rule.id}: a ${rule.action.kind} action needs a numeric ${name}`);
  }
  return value;
}

export function stringParameter(rule: Rule, name: string): string | undefined {
  const value = rule.action[name];
  if (value !== undefined && typeof value !== "string") {
    throw new Error(`rule ${rule.id}: the ${name} of a ${rule.action.kind} action is a string`);
  }
  return value;
}
