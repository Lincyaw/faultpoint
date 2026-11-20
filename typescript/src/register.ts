import { registerHooks } from "node:module";
import { relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { OtelContext } from "./context.js";
import { CORE, type Core, type Plugin } from "./core.js";
import { httpPlugin } from "./http.js";
import { JsonlOptions, JsonlSink } from "./observations.js";
import { pointsPlugin } from "./points.js";
import { FileRuleSource } from "./rules.js";
import { instrumentModule } from "./transform.js";

const RULES_POLL_MS = 500;

/** Places points in the modules under the source root, outside node_modules, as Node loads them. */
const loadHookPlugin: Plugin = {
  name: "load-hook",
  install(core: Core) {
    const { sourceRoot, service, config } = core.settings;
    registerHooks({
      load(url, context, nextLoad) {
        const result = nextLoad(url, context);
        if (!url.startsWith("file:") || (result.format !== "module" && result.format !== "commonjs")
          || result.source === undefined || result.source === null) {
          return result;
        }
        const path = relative(sourceRoot, fileURLToPath(url));
        if (path.startsWith("..") || path.split(sep).includes("node_modules")) {
          return result;
        }
        const { code } = instrumentModule(result.source.toString(), path.split(sep).join("/"), service, config.placement);
        return code === null ? result : { ...result, source: code };
      },
    });
  },
};

const BUILTIN_PLUGINS: ReadonlyMap<string, Plugin> = new Map(
  [pointsPlugin, loadHookPlugin, httpPlugin].map((plugin) => [plugin.name, plugin]));

/** A built-in plugin, or the default export of the package of that name. */
async function resolvePlugin(name: string): Promise<Plugin> {
  return BUILTIN_PLUGINS.get(name) ?? (await import(name)).default as Plugin;
}

async function attach(core: Core): Promise<void> {
  const { settings } = core;
  core.useContext(new OtelContext());
  if (settings.report !== null) {
    core.useSink(new JsonlSink(settings.report, settings.service, JsonlOptions.parse(settings.config.options.jsonl ?? {})));
  }
  if (settings.rules !== null) {
    core.useRuleSource(new FileRuleSource(settings.rules, RULES_POLL_MS, (reason) => core.abort(reason)));
  }
  for (const name of settings.config.plugins) {
    const plugin = await resolvePlugin(name);
    await plugin.install(core, settings.config.options[name] ?? {});
  }
  core.start();
}

// Loaded by `node --import faultpoint/register`, so that business code and its build stay free of the SDK.
if (CORE.enabled) {
  await attach(CORE);
}
