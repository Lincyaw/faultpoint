#!/usr/bin/env node
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";

import { Config } from "./config.js";
import { type PointEntry, instrumentModule } from "./transform.js";

const MANIFEST_FILE = "faultpoint-manifest.json";
const MODULE_EXTENSIONS = [".js", ".mjs", ".cjs"];

/** The points the load hook would place under a source root, found by the same transform so that the ids agree. */
function scan(root: string, service: string, config: Config): PointEntry[] {
  return readdirSync(root, { recursive: true, encoding: "utf-8" })
    .filter((path) => MODULE_EXTENSIONS.some((extension) => path.endsWith(extension))
      && !path.split("/").includes("node_modules"))
    .sort()
    .flatMap((path) => instrumentModule(readFileSync(join(root, path), "utf-8"), path, service, config.placement).points);
}

const { values } = parseArgs({
  options: { service: { type: "string" }, root: { type: "string" }, config: { type: "string" } },
});
if (!values.service || !values.root) {
  console.error("usage: faultpoint-scan --service NAME --root SOURCE_ROOT [--config FAULTPOINT_CONFIG]");
  process.exit(2);
}
const root = resolve(values.root);
const config = Config.parse(values.config ? JSON.parse(readFileSync(values.config, "utf-8")) : {});
const points = scan(root, values.service, config);
writeFileSync(join(root, MANIFEST_FILE),
  `${JSON.stringify({ service: values.service, language: "typescript", points }, null, 2)}\n`);
console.log(`${points.length} points in ${root}`);
