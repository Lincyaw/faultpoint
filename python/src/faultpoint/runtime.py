import atexit
import functools
import os
import random
import sys
import threading
import time
import traceback
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from importlib.metadata import entry_points
from typing import Annotated, Final, NoReturn, Union

from pydantic import BaseModel, ConfigDict, Field, JsonValue, TypeAdapter

from faultpoint.config import Config, Settings
from faultpoint.context import ContextProvider, OtelContext
from faultpoint.observations import (JSONL_OPTIONS, JsonlOptions, JsonlSink, Observation,
                                     ObservationSink)
from faultpoint.rules import FileRuleSource, Rule, RuleSet, RuleSource

PLUGIN_GROUP: Final = "faultpoint.plugins"
POLL_INTERVAL_S: Final = 0.5
STOP_EXIT_CODE: Final = 70


def implemented_actions(*models: type[BaseModel]) -> object:
    """The actions a plugin implements at one kind, a union the models' `kind` fields discriminate."""
    return Annotated[Union[models], Field(discriminator="kind")]


class Decision(BaseModel):
    """A rule of this process with the action its plugin parsed from it."""

    model_config = ConfigDict(frozen=True)

    rule: Rule
    action: BaseModel


class RulesInForce:
    """The rule set a process obeys, its rules by point, and how often each rule matched and injected."""

    def __init__(self, experiment: str, decisions: Iterable[Decision], seed: int) -> None:
        self.experiment = experiment
        self.by_point: dict[str, tuple[Decision, ...]] = {}
        for decision in decisions:
            self.by_point[decision.rule.point] = (*self.by_point.get(decision.rule.point, ()), decision)
        self.lock = threading.Lock()
        self.matches: Counter[str] = Counter()
        self.injections: Counter[str] = Counter()
        self.randoms = {decision.rule.id: random.Random(f"{seed}:{decision.rule.id}")
                        for decisions in self.by_point.values() for decision in decisions}

    def fires(self, rule: Rule) -> bool:
        """Count a matching execution, and whether the rule's trigger injects at it."""
        trigger = rule.trigger
        with self.lock:
            seen = self.matches[rule.id]
            self.matches[rule.id] = seen + 1
            fired = (seen >= trigger.skip
                     and (trigger.limit is None or self.injections[rule.id] < trigger.limit)
                     and self.randoms[rule.id].random() < trigger.probability)
            if fired:
                self.injections[rule.id] += 1
        return fired


class Runtime:
    """The kinds this process's plugins serve, the rules it obeys, and where its observations go."""

    def __init__(self, settings: Settings, config: Config, plugins: Mapping[str, "Plugin"]) -> None:
        self.settings = settings
        self.config = config
        self.kinds: dict[str, TypeAdapter[dict[str, BaseModel]]] = {}
        for name, plugin in plugins.items():
            for kind, actions in plugin.actions.items():
                if kind in self.kinds:
                    raise ValueError(f"plugin {name} serves the kind {kind}, which another plugin serves")
                self.kinds[kind] = TypeAdapter(dict[str, actions])
        self.context = provided((plugin.context for plugin in plugins.values()), otel_context)(config)
        self.sink = provided((plugin.sink for plugin in plugins.values()), jsonl_sink)(settings, config)
        self.rules = RulesInForce("", (), settings.seed)

    def load(self, ruleset: RuleSet) -> None:
        """Obey a rule set once the plugins that serve the kinds of its rules here parse their actions."""
        applicable = [rule for rule in ruleset.rules
                      if rule.service == self.settings.service and rule.kind in self.kinds]
        actions: dict[str, BaseModel] = {}
        for kind, adapter in self.kinds.items():
            actions |= adapter.validate_python(
                {rule.id: rule.action.model_dump() for rule in applicable if rule.kind == kind})
        if self.sink is not None:
            self.sink.flush()
        self.rules = RulesInForce(ruleset.experiment,
                                  (Decision(rule=rule, action=actions[rule.id]) for rule in applicable),
                                  self.settings.seed)

    def reload(self, source: RuleSource) -> None:
        ruleset = source.poll()
        if ruleset is not None:
            self.load(ruleset)

    def decide(self, point: str) -> Decision | None:
        """The first rule of a point whose scope matches the current request and whose trigger fires now."""
        rules = self.rules
        return next((decision for decision in rules.by_point.get(point, ())
                     if all(self.context.baggage(key) == value
                            for key, value in decision.rule.scope.items())
                     and rules.fires(decision.rule)), None)

    def observe(self, point: str, outcome: str, quantity: float, decision: Decision | None) -> None:
        if self.sink is not None:
            self.sink.add(Observation(
                experiment=self.rules.experiment, point=point, outcome=outcome,
                scope=self.context.baggage(self.settings.scope_key) or "",
                rule=None if decision is None else decision.rule.id, quantity=quantity,
                trace_id=self.context.trace_id()))

    def crash(self, code: int) -> NoReturn:
        if self.sink is not None:
            self.sink.flush()
        os._exit(code)


class Plugin(BaseModel):
    """The actions a plugin implements per kind, its installation, and the components it replaces."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    actions: dict[str, object] = Field(default_factory=dict)
    install: Callable[[Runtime, dict[str, JsonValue]], None] | None = None
    """Called with the options the configuration gives under the plugin's name."""
    source: Callable[[Settings, Config], RuleSource | None] | None = None
    sink: Callable[[Settings, Config], ObservationSink | None] | None = None
    context: Callable[[Config], ContextProvider] | None = None


def provided[T](factories: Iterable[T | None], default: T) -> T:
    """The factory of a component that one plugin provides, or the default when none does."""
    present = [factory for factory in factories if factory is not None]
    if len(present) > 1:
        raise ValueError("two plugins provide the same component")
    return present[0] if present else default


def otel_context(config: Config) -> ContextProvider:
    return OtelContext()


def jsonl_sink(settings: Settings, config: Config) -> ObservationSink | None:
    return None if settings.report is None else JsonlSink(
        settings.report, settings.service,
        JsonlOptions.model_validate(config.options.get(JSONL_OPTIONS, {})))


def file_rule_source(settings: Settings, config: Config) -> RuleSource | None:
    return None if settings.rules is None else FileRuleSource(settings.rules)


def stop() -> NoReturn:
    """End the process, so that no experiment runs without the rules and plugins it asked for."""
    traceback.print_exc()
    print("faultpoint: stopping the process", file=sys.stderr, flush=True)
    os._exit(STOP_EXIT_CODE)


def repeat(interval: float, step: Callable[[], None]) -> NoReturn:
    while True:
        time.sleep(interval)
        try:
            step()
        except Exception:
            stop()


RUNTIME: Runtime
"""The runtime of a process in which faultpoint is enabled, which placed points use."""


def start() -> None:
    """Enable faultpoint in this process: load its plugins, obey its rules, then install the plugins."""
    global RUNTIME
    try:
        settings = Settings()
        config = Config.read(settings.config)
        available = {point.name: point for point in entry_points(group=PLUGIN_GROUP)}
        plugins: dict[str, Plugin] = {name: available[name].load() for name in config.plugins}
        RUNTIME = Runtime(settings, config, plugins)
        source = provided((plugin.source for plugin in plugins.values()), file_rule_source)(settings, config)
        if source is not None:
            RUNTIME.reload(source)
            threading.Thread(target=repeat, args=(POLL_INTERVAL_S, functools.partial(RUNTIME.reload, source)),
                             name="faultpoint-rules", daemon=True).start()
        for name, plugin in plugins.items():
            if plugin.install is not None:
                plugin.install(RUNTIME, config.options.get(name, {}))
        if RUNTIME.sink is not None:
            atexit.register(RUNTIME.sink.flush)
            threading.Thread(target=repeat, args=(RUNTIME.sink.interval, RUNTIME.sink.flush),
                             name="faultpoint-observations", daemon=True).start()
    except Exception:
        stop()
