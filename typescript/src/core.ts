import { createHash } from "node:crypto";

import { type Settings, settingsFromEnvironment } from "./config.js";
import { type Rule, type RuleSet, pointParts } from "./rules.js";

const INVALID_RULES_EXIT = 70;

/** One execution of a point, as the core hands it to the observation sink; the detail tells executions of one outcome
 * apart by bounded values under the keys spec/kinds.json gives the kind. */
export interface Observation {
  experiment: string;
  point: string;
  outcome: string;
  scope: string;
  rule: string | null;
  quantity: number;
  traceId: string | null;
  detail: Readonly<Record<string, string>>;
}

/** How a detail names an error: its code when it has a textual one, as Node's system errors do, otherwise its name. */
export function errorName(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" ? code : error instanceof Error ? error.name : typeof error;
}

export interface RuleSource {
  start(apply: (ruleset: RuleSet) => void): void;
}

export interface ObservationSink {
  add(observation: Observation): void;
  flush(): void;
}

export interface ContextProvider {
  baggage(key: string): string | undefined;
  traceId(): string | null;
}

/** A plugin is installed by name from the configuration, with the options given under its name. */
export interface Plugin {
  readonly name: string;
  install(core: Core, options: Record<string, unknown>): void | Promise<void>;
}

/** A seeded generator, so that a probabilistic trigger fires at the same executions in every repetition. */
function seededRandom(seed: string): () => number {
  let drawn = 0;
  return () => createHash("sha256").update(`${seed}:${drawn++}`).digest().readUInt32BE(0) / 2 ** 32;
}

/** Obtains rules, selects the rule of an execution and hands observations to the sink; every kind's
 * semantics lives in the plugins, which declare the kinds they serve and the actions they implement. */
/** The locators of every point of a kind, for a plugin that serves them all. */
export const EVERY_LOCATOR = (): boolean => true;

/** fail_after acts only on an operation that completed normally, so a point decides and counts it only then; every
 * other action acts before the operation. */
export const ACTS_AFTER = (action: string): boolean => action === "fail_after";
export const ACTS_BEFORE = (action: string): boolean => action !== "fail_after";

/** The kinds one plugin serves with the actions it implements there, at the points whose locators it serves. */
interface Declaration {
  readonly kinds: Readonly<Record<string, readonly string[]>>;
  readonly locators: (locator: string) => boolean;
}

export class Core {
  readonly enabled: boolean;
  readonly declarations: Declaration[] = [];
  /** Each answers why its plugin cannot obey a rule, or null; a plugin passes over the kinds it does not serve. */
  readonly checks: Array<(rule: Rule) => string | null> = [];
  experiment = "";
  rules = new Map<string, Rule[]>();
  matches = new Map<string, number>();
  injections = new Map<string, number>();
  randoms = new Map<string, () => number>();
  source: RuleSource | null = null;
  sink: ObservationSink | null = null;
  context: ContextProvider | null = null;

  constructor(readonly settings: Settings) {
    this.enabled = settings.rules !== null || settings.report !== null;
    if (this.enabled && settings.service === "") {
      throw new Error("FAULTPOINT_SERVICE is required when faultpoint is enabled");
    }
  }

  /** The kinds a plugin serves with the actions it implements there, at the points whose locators have the shape its
   * adapter makes. A point served by several plugins accepts only the actions every one of them implements, so that a
   * rule is rejected when its rule set loads rather than at the one point that cannot obey it. */
  declare(kinds: Readonly<Record<string, readonly string[]>>, locators: (locator: string) => boolean): void {
    this.declarations.push({ kinds, locators });
  }

  /** A check of every rule of this service when its rule set loads, for what an action's parameters ask that a plugin
   * cannot do, so that the rule set is refused rather than one point failing to obey it. */
  check(refusal: (rule: Rule) => string | null): void {
    this.checks.push(refusal);
  }

  useRuleSource(source: RuleSource): void {
    this.source = source;
  }

  useSink(sink: ObservationSink): void {
    this.sink = sink;
  }

  useContext(context: ContextProvider): void {
    this.context = context;
  }

  start(): void {
    this.source?.start((ruleset) => this.apply(ruleset));
  }

  /** Install a rule set; a rule of this service at a point plugins serve must use an action each of those plugins
   * implements, a rule of a kind plugins here serve at a point none of them serves is refused, and rules of other
   * services or of kinds no plugin here serves are left to their processes. */
  apply(ruleset: RuleSet): void {
    const rules = new Map<string, Rule[]>();
    for (const rule of ruleset.rules) {
      const { service, kind, locator } = pointParts(rule.point);
      const ofKind = this.declarations.filter((declaration) => declaration.kinds[kind] !== undefined);
      if (service !== this.settings.service || ofKind.length === 0) {
        continue;
      }
      const serving = ofKind.filter((declaration) => declaration.locators(locator)).map((declaration) => declaration.kinds[kind]);
      if (serving.length === 0) {
        this.abort(`rule ${rule.id}: no plugin of this process serves ${rule.point}`);
      }
      if (!serving.every((actions) => actions.includes(rule.action.kind))) {
        this.abort(`rule ${rule.id}: not every plugin of this process serving its point implements ${rule.action.kind} at ${rule.point}`);
      }
      for (const check of this.checks) {
        const refusal = check(rule);
        if (refusal !== null) {
          this.abort(`rule ${rule.id}: ${refusal}`);
        }
      }
      rules.set(rule.point, [...(rules.get(rule.point) ?? []), rule]);
    }
    this.sink?.flush();
    this.experiment = ruleset.experiment;
    this.rules = rules;
    this.matches = new Map();
    this.injections = new Map();
    this.randoms = new Map(ruleset.rules.map((rule) => [rule.id, seededRandom(`${this.settings.seed}:${rule.id}`)]));
  }

  /** The first rule of a point whose scope matches the current request and whose trigger fires. */
  decide(point: string): Rule | null {
    return this.decideAmong(point, () => true);
  }

  /** The first rule of a point among the rules of the given actions whose scope matches the current request and
   * whose trigger fires. Only those rules are counted, so that a point deciding before and after its operation counts
   * a rule only where it can act. */
  decideAmong(point: string, actions: (action: string) => boolean): Rule | null {
    for (const rule of this.rules.get(point) ?? []) {
      if (!actions(rule.action.kind) || !Object.entries(rule.scope).every(([key, value]) => this.context?.baggage(key) === value)) {
        continue;
      }
      const seen = this.matches.get(rule.id) ?? 0;
      this.matches.set(rule.id, seen + 1);
      const injected = this.injections.get(rule.id) ?? 0;
      if (seen < rule.trigger.skip || (rule.trigger.limit !== null && injected >= rule.trigger.limit)) {
        continue;
      }
      if (this.randoms.get(rule.id)!() >= rule.trigger.probability) {
        continue;
      }
      this.injections.set(rule.id, injected + 1);
      return rule;
    }
    return null;
  }

  observe(point: string, outcome: string, quantity: number, rule: Rule | null, detail: Readonly<Record<string, string>>): void {
    this.sink?.add({
      experiment: this.experiment, point, outcome, quantity, rule: rule?.id ?? null,
      scope: this.context?.baggage(this.settings.scopeKey) ?? "", traceId: this.context?.traceId() ?? null, detail,
    });
  }

  crash(code: number): never {
    this.sink?.flush();
    process.exit(code);
  }

  /** End the process when rules cannot be obeyed, so that no experiment runs under rules it did not ask for. */
  abort(reason: string): never {
    console.error(`faultpoint: ${reason}; stopping the process`);
    this.sink?.flush();
    process.exit(INVALID_RULES_EXIT);
  }
}

export const CORE = new Core(settingsFromEnvironment());
