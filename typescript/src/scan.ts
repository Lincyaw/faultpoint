#!/usr/bin/env node
import { readFileSync, readdirSync, realpathSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";

import { Config, packageOf, targetOf } from "./config.js";
import { type PointEntry, instrumentModule } from "./transform.js";

const MANIFEST_FILE = "faultpoint-manifest.json";
const MODULE_EXTENSIONS = [".js", ".mjs", ".cjs"];

function modules(directory: string): string[] {
  return readdirSync(directory, { recursive: true, encoding: "utf-8" })
    .filter((path) => MODULE_EXTENSIONS.some((extension) => path.endsWith(extension)))
    .sort()
    .map((path) => join(directory, path));
}

/** The points the load hook would place in the business code under a source root and in the packages the
 * placement scope names, found by the same transform and targets so that the ids agree. */
function scan(root: string, service: string, config: Config): PointEntry[] {
  const require = createRequire(join(root, "package.json"));
  // A package's own package.json may be outside its exports, so the package is found from its entry module.
  const packages = config.placement.scope.map((entry) => {
    const installed = packageOf(realpathSync(require.resolve(entry.include)));
    if (installed === null) {
      throw new Error(`${entry.include} does not resolve into node_modules from ${root}`);
    }
    return installed.root;
  });
  const files = [...modules(root).filter((file) => !file.includes("/node_modules/")), ...packages.flatMap(modules)];
  return files.flatMap((file) => {
    const target = targetOf(file, root, config.placement);
    return target === null ? [] : instrumentModule(readFileSync(file, "utf-8"), `${target.prefix}${target.path}`, service,
      config.placement, target.kinds).points;
  });
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
