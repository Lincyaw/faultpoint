import { appendFileSync } from "node:fs";
import { hostname } from "node:os";

import { z } from "zod";

import { CORE, type Observation, type ObservationSink } from "./core.js";

/** One line of an observation file, as spec/observation.schema.json defines. */
export interface ObservationRecord {
  experiment: string;
  service: string;
  process: string;
  start: number;
  end: number;
  point: string;
  outcome: string;
  scope: string;
  rule: string | null;
  count: number;
  total: number;
  exemplars: string[];
  detail: Record<string, string>;
}

export const JsonlOptions = z.strictObject({
  flush_seconds: z.number().positive().default(2),
  exemplars: z.number().int().min(0).default(5),
  /** The share of traces whose ids are kept as exemplars, for hot library paths; counts stay exact. */
  exemplar_rate: z.number().min(0).max(1).default(1),
});

/** The default observation sink: observations aggregated per window and appended as JSON Lines. */
export class JsonlSink implements ObservationSink {
  readonly process = `${hostname()}:${process.pid}`;
  tally = new Map<string, ObservationRecord>();
  windowStart = Date.now() / 1000;

  constructor(readonly path: string, readonly service: string, readonly options: z.infer<typeof JsonlOptions>) {
    // A timer's error would reach the application's uncaughtException handler, which may keep the process running without its observations.
    setInterval(() => CORE.own(() => this.flush()), options.flush_seconds * 1000).unref();
    process.on("exit", () => this.flush());
  }

  add(observation: Observation): void {
    // The detail's entries are sorted, so that one detail is one key and its record lists the keys in order.
    const detail = Object.entries(observation.detail).sort(([one], [other]) => (one < other ? -1 : 1));
    const key = JSON.stringify([observation.experiment, observation.point, observation.outcome, observation.scope,
      observation.rule, detail]);
    const record = this.tally.get(key) ?? {
      experiment: observation.experiment, service: this.service, process: this.process, start: 0, end: 0,
      point: observation.point, outcome: observation.outcome, scope: observation.scope, rule: observation.rule,
      count: 0, total: 0, exemplars: [], detail: Object.fromEntries(detail),
    };
    record.count += 1;
    record.total += observation.quantity;
    // A trace is sampled by its id, so that every process keeps or skips the same traces.
    if (observation.traceId !== null && record.exemplars.length < this.options.exemplars
      && parseInt(observation.traceId.slice(-8), 16) % 10_000 < this.options.exemplar_rate * 10_000) {
      record.exemplars.push(observation.traceId);
    }
    this.tally.set(key, record);
  }

  flush(): void {
    const end = Date.now() / 1000;
    const lines = [...this.tally.values()].map(
      (record) => `${JSON.stringify({ ...record, start: this.windowStart, end })}\n`);
    this.tally = new Map();
    this.windowStart = end;
    if (lines.length > 0) {
      appendFileSync(this.path, lines.join(""));
    }
  }
}
