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
export class Core {
  readonly enabled: boolean;
  readonly declared = new Map<string, ReadonlySet<string>>();
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

  /** A kind served by several plugins accepts only the actions every one of them implements, so that a rule is
   * rejected when its rule set loads rather than at the one point that cannot obey it. */
  declare(kinds: Readonly<Record<string, readonly string[]>>): void {
    for (const [kind, actions] of Object.entries(kinds)) {
      const known = this.declared.get(kind);
      this.declared.set(kind, new Set(known === undefined ? actions : actions.filter((action) => known.has(action))));
    }
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

  /** Install a rule set; a rule of this service for a kind a plugin serves must use an action that
   * plugin implements, and rules of other services or kinds are left to the processes that serve them. */
  apply(ruleset: RuleSet): void {
    const rules = new Map<string, Rule[]>();
    for (const rule of ruleset.rules) {
      const { service, kind } = pointParts(rule.point);
      const actions = this.declared.get(kind);
      if (service !== this.settings.service || actions === undefined) {
        continue;
      }
      if (!actions.has(rule.action.kind)) {
        this.abort(`rule ${rule.id}: not every plugin of this process serving it implements ${rule.action.kind} at a ${kind} point`);
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
    for (const rule of this.rules.get(point) ?? []) {
      if (!Object.entries(rule.scope).every(([key, value]) => this.context?.baggage(key) === value)) {
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
