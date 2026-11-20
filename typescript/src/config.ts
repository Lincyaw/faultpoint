import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";

import { z } from "zod";

export const DEFAULT_PLUGINS = ["points", "load-hook", "http", "pg", "ioredis"];

/** A CommonJS package as the application under the source root resolves it, so that a patch reaches the very
 * module instance the application imports; null when the application does not depend on it. */
export function applicationModule<T>(sourceRoot: string, name: string): T | null {
  const require = createRequire(join(sourceRoot, "package.json"));
  try {
    return require(name) as T;
  } catch (error) {
    if ((error as { code?: string }).code === "MODULE_NOT_FOUND" && (error as Error).message.includes(`'${name}'`)) {
      return null;
    }
    throw error;
  }
}

/** The global placed code reaches the point functions through, so that CommonJS and ES modules need no import. */
export const POINTS_SYMBOL = "faultpoint";

/** An installed package whose code gets points, limited to some kinds when kinds is given. */
export const ScopeEntry = z.strictObject({
  include: z.string().min(1),
  kinds: z.array(z.string()).optional(),
});
export type ScopeEntry = z.infer<typeof ScopeEntry>;

/** Where every placement rule can be switched off and its name lists replaced, and which installed packages get
 * points besides the business code under the source root. */
export const Placement = z.strictObject({
  branch: z.boolean().default(true),
  check: z.boolean().default(true),
  loop: z.boolean().default(true),
  clock: z.array(z.string()).default(["Date.now", "new Date"]),
  scope: z.array(ScopeEntry).default([]),
  exclude: z.array(z.string()).default([]),
});
export type Placement = z.infer<typeof Placement>;

/** Packages that never get points: the SDK, what it observes through, and logging. */
export const ALWAYS_EXCLUDED = ["faultpoint", "@opentelemetry/", "pino", "winston", "debug", "loglevel", "bunyan", "log4js"];

export const Config = z.strictObject({
  plugins: z.array(z.string()).default(DEFAULT_PLUGINS),
  options: z.record(z.string(), z.record(z.string(), z.unknown())).default({}),
  placement: Placement.default({
    branch: true, check: true, loop: true, clock: ["Date.now", "new Date"], scope: [], exclude: [],
  }),
});

/** Where the points of a module go: the prefix of their locators, and the kinds allowed there (undefined: every kind). */
export interface Target {
  readonly prefix: string;
  readonly kinds?: readonly string[];
}

/** The package a file under node_modules belongs to, with the directory it is installed in. */
export function packageOf(file: string): { name: string; root: string } | null {
  const marker = "/node_modules/";
  const at = file.lastIndexOf(marker);
  if (at < 0) {
    return null;
  }
  const segments = file.slice(at + marker.length).split("/");
  const name = segments[0].startsWith("@") ? `${segments[0]}/${segments[1]}` : segments[0];
  return { name, root: file.slice(0, at + marker.length) + name };
}

const VERSIONS = new Map<string, string>();

/** Where the points of a module file go, or null when it gets none: business code under the source root keeps
 * paths relative to it, and an in-scope package carries its name and installed version. */
export function targetOf(file: string, sourceRoot: string, placement: Placement): (Target & { path: string }) | null {
  const installed = packageOf(file);
  if (installed === null) {
    const inside = file.startsWith(`${sourceRoot}/`);
    return inside ? { prefix: "", path: file.slice(sourceRoot.length + 1) } : null;
  }
  const excluded = [...ALWAYS_EXCLUDED, ...placement.exclude];
  const entry = placement.scope.find((candidate) => candidate.include === installed.name);
  if (entry === undefined || excluded.some((name) => installed.name === name || (name.endsWith("/") && installed.name.startsWith(name)))) {
    return null;
  }
  let version = VERSIONS.get(installed.root);
  if (version === undefined) {
    version = (JSON.parse(readFileSync(join(installed.root, "package.json"), "utf-8")) as { version: string }).version;
    VERSIONS.set(installed.root, version);
  }
  return { prefix: `${installed.name}@${version}/`, kinds: entry.kinds, path: file.slice(installed.root.length + 1) };
}
export type Config = z.infer<typeof Config>;

export interface Settings {
  readonly service: string;
  readonly rules: string | null;
  readonly report: string | null;
  readonly sourceRoot: string;
  readonly scopeKey: string;
  readonly seed: number;
  readonly config: Config;
}

/** The settings of the FAULTPOINT_ environment variables and of the file FAULTPOINT_CONFIG names. */
export function settingsFromEnvironment(): Settings {
  const seed = Number(process.env.FAULTPOINT_SEED ?? "0");
  if (!Number.isInteger(seed)) {
    throw new Error("FAULTPOINT_SEED is an integer");
  }
  const configPath = process.env.FAULTPOINT_CONFIG;
  return {
    service: process.env.FAULTPOINT_SERVICE ?? "",
    rules: process.env.FAULTPOINT_RULES || null,
    report: process.env.FAULTPOINT_REPORT || null,
    sourceRoot: process.env.FAULTPOINT_SOURCE_ROOT || process.cwd(),
    scopeKey: process.env.FAULTPOINT_SCOPE_KEY || "fp.scope",
    seed,
    config: Config.parse(configPath ? JSON.parse(readFileSync(configPath, "utf-8")) : {}),
  };
}
