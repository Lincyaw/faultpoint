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

/** Where every placement rule can be switched off and its name lists replaced. */
export const Placement = z.strictObject({
  branch: z.boolean().default(true),
  check: z.boolean().default(true),
  loop: z.boolean().default(true),
  clock: z.array(z.string()).default(["Date.now", "new Date"]),
});
export type Placement = z.infer<typeof Placement>;

export const Config = z.strictObject({
  plugins: z.array(z.string()).default(DEFAULT_PLUGINS),
  options: z.record(z.string(), z.record(z.string(), z.unknown())).default({}),
  placement: Placement.default({ branch: true, check: true, loop: true, clock: ["Date.now", "new Date"] }),
});
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
