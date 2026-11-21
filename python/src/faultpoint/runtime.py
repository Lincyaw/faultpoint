import atexit
import functools
import os
import random
import signal
import sys
import threading
import time
import traceback
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from enum import StrEnum
from importlib.metadata import entry_points
from types import FrameType
from typing import Annotated, Final, NoReturn, Union

from pydantic import BaseModel, ConfigDict, Field, JsonValue, TypeAdapter, ValidationError
from pydantic_core import ErrorDetails

from faultpoint.actions import OnCompletion
from faultpoint.config import Config, Settings
from faultpoint.context import ContextProvider, OtelContext
from faultpoint.observations import (JSONL_OPTIONS, NO_DETAIL, JsonlOptions, JsonlSink, Observation,
                                     ObservationSink)
from faultpoint.rules import FileRuleSource, Rule, RuleSet, RuleSource

PLUGIN_GROUP: Final = "faultpoint.plugins"
POLL_INTERVAL_S: Final = 0.5
STOP_EXIT_CODE: Final = 70
DEFAULT_DISPOSITIONS: Final = {signal.SIGTERM: signal.SIG_DFL, signal.SIGINT: signal.default_int_handler}
"""The stopping signals with the dispositions Python starts with; the observations are flushed on a signal whose
disposition the application has not changed by the time faultpoint starts."""


def implemented_actions(*models: type[BaseModel]) -> object:
    """The actions a plugin implements at one kind, a union the models' `kind` fields discriminate."""
    return Annotated[Union[models], Field(discriminator="kind")]


class Decision(BaseModel):
    """A rule of this process with the action its plugin parsed from it."""

    model_config = ConfigDict(frozen=True)

    rule: Rule
    action: BaseModel


class RulesInForce:
    """The rule set a process obeys, its rules by point, those decided before the point's operation runs apart from
    those decided once it completed, and how often each rule matched and injected."""

    def __init__(self, experiment: str, decisions: Iterable[Decision], seed: int) -> None:
        self.experiment = experiment
        self.before: dict[str, tuple[Decision, ...]] = {}
        self.on_completion: dict[str, tuple[Decision, ...]] = {}
        rules = tuple(decisions)
        for decision in rules:
            by_point = self.on_completion if isinstance(decision.action, OnCompletion) else self.before
            by_point[decision.rule.point] = (*by_point.get(decision.rule.point, ()), decision)
        self.lock = threading.Lock()
        self.matches: Counter[str] = Counter()
        self.injections: Counter[str] = Counter()
        self.randoms = {decision.rule.id: random.Random(f"{seed}:{decision.rule.id}") for decision in rules}

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


class RuleRefused(ValueError):
    """A rule set this process cannot obey, with one line per refused rule, as every SDK words a refusal."""


class IssueType(StrEnum):
    """The pydantic error types a refusal words itself."""

    UNKNOWN_ACTION = "union_tag_invalid"
    UNIMPORTABLE = "import_error"


def refusal(kind: str, issue: ErrorDetails) -> str:
    """One rule a kind's plugins refused, in an operator's words."""
    rule, *location = issue["loc"]
    match issue:
        case {"type": IssueType.UNKNOWN_ACTION, "ctx": {"tag": action}}:
            problem = f"no plugin of this process implements {action} at a {kind} point"
        case {"type": IssueType.UNIMPORTABLE, "input": name, "ctx": {"error": reason}}:
            problem = f"cannot import the error class {name}: {reason}"
        case _:
            problem = f"{'.'.join(map(str, location))}: {issue['msg']}"
    return f"rule {rule}: {problem}"


class KindServer(BaseModel):
    """A plugin serving a kind: the actions it parses, and which of the kind's points it serves by their locators;
    None serves them all."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    actions: TypeAdapter[dict[str, BaseModel]]
    serves: Callable[[str], bool] | None


class Runtime:
    """The kinds this process's plugins serve, the rules it obeys, and where its observations go."""

    def __init__(self, settings: Settings, config: Config, plugins: Mapping[str, "Plugin"]) -> None:
        self.settings = settings
        self.config = config
        self.kinds: dict[str, list[KindServer]] = {}
        for name, plugin in plugins.items():
            serves = None if plugin.serves is None else plugin.serves(config.options.get(name, {}))
            for kind, actions in plugin.actions.items():
                self.kinds.setdefault(kind, []).append(
                    KindServer(actions=TypeAdapter(dict[str, actions]), serves=serves))
        self.context = provided((plugin.context for plugin in plugins.values()), otel_context)(config)
        self.sink = provided((plugin.sink for plugin in plugins.values()), jsonl_sink)(settings, config)
        self.rules = RulesInForce("", (), settings.seed)

    def load(self, ruleset: RuleSet) -> None:
        """Obey a rule set once every plugin here that serves the point of one of its rules parses its action."""
        applicable = [rule for rule in ruleset.rules
                      if rule.service == self.settings.service and rule.kind in self.kinds]
        actions: dict[str, BaseModel] = {}
        problems: list[str] = []
        for rule in applicable:
            servers = [server for server in self.kinds[rule.kind]
                       if server.serves is None or server.serves(rule.locator)]
            if not servers:
                problems.append(f"rule {rule.id}: no plugin of this process serves {rule.point}")
            for server in servers:
                try:
                    actions |= server.actions.validate_python({rule.id: rule.action.model_dump()})
                except ValidationError as error:
                    problems.extend(refusal(rule.kind, issue) for issue in error.errors())
        if problems:
            # Plugins that parse a rule into the same models refuse it in the same words.
            raise RuleRefused("\n".join(dict.fromkeys(problems)))
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
        """The first rule of a point decided before its operation runs whose scope matches the current request and
        whose trigger fires now."""
        rules = self.rules
        return self.fired(rules, rules.before.get(point, ()))

    def decide_completed(self, point: str) -> Decision | None:
        """The first rule of a point decided once its operation completed normally, such as a fail_after, whose
        scope matches the current request and whose trigger fires now; an operation that failed by itself is never
        decided this way."""
        rules = self.rules
        return self.fired(rules, rules.on_completion.get(point, ()))

    def fired(self, rules: RulesInForce, decisions: Iterable[Decision]) -> Decision | None:
        return next((decision for decision in decisions
                     if all(self.context.baggage(key) == value for key, value in decision.rule.scope.items())
                     and rules.fires(decision.rule)), None)

    def observe(self, point: str, outcome: str, quantity: float, decision: Decision | None,
                detail: Mapping[str, str] = NO_DETAIL) -> None:
        if self.sink is not None:
            self.sink.add(Observation(
                experiment=self.rules.experiment, point=point, outcome=outcome,
                scope=self.context.baggage(self.settings.scope_key) or "",
                rule=None if decision is None else decision.rule.id, quantity=quantity,
                trace_id=self.context.trace_id(), detail=dict(detail)))

    def crash(self, code: int) -> NoReturn:
        if self.sink is not None:
            self.sink.flush()
        os._exit(code)

    def refuse(self, decision: Decision, problem: str) -> NoReturn:
        """Stop the process at a rule the point it fires at cannot obey, which loading could not tell, since the id
        of a point that several plugins serve does not say which of them reaches it; the observations so far are
        kept."""
        if self.sink is not None:
            self.sink.flush()
        stop(RuleRefused(f"rule {decision.rule.id}: {problem}"))


class Plugin(BaseModel):
    """The actions a plugin implements per kind, its installation, and the components it replaces."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    actions: dict[str, object] = Field(default_factory=dict)
    """The actions per kind; plugins serving one point parse its actions into the same models, since its id does
    not say which of them reaches it."""
    serves: Callable[[dict[str, JsonValue]], Callable[[str], bool]] | None = None
    """Which points of its kinds the plugin serves, by the shape of the locators its adapter gives, built from its
    options; None serves them all. A rule is held only to the plugins that serve its point."""
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


def stop(error: Exception) -> NoReturn:
    """End the process, so that no experiment runs without the rules and plugins it asked for; a refused rule set
    is reported rule by rule, any other failure by its traceback."""
    if isinstance(error, RuleRefused):
        print("\n".join(f"faultpoint: {line}" for line in str(error).splitlines()), file=sys.stderr)
    else:
        traceback.print_exception(error)
    print("faultpoint: stopping the process", file=sys.stderr, flush=True)
    os._exit(STOP_EXIT_CODE)


def flush_then_resignal(sink: ObservationSink, signum: int, frame: FrameType | None) -> None:
    """Write the observations before a stopping signal has its default effect, which for SIGTERM ends the process
    without its exit handlers, so that a process stopped gracefully loses none of them."""
    # The main thread the signal interrupted may hold the sink's lock, so the flush waits for it at most an interval.
    flushing = threading.Thread(target=sink.flush, name="faultpoint-final-flush", daemon=True)
    flushing.start()
    flushing.join(sink.interval)
    signal.signal(signum, DEFAULT_DISPOSITIONS[signal.Signals(signum)])
    signal.raise_signal(signum)


def repeat(interval: float, step: Callable[[], None]) -> NoReturn:
    while True:
        time.sleep(interval)
        try:
            step()
        except Exception as error:
            stop(error)


RUNTIME: Runtime
"""The runtime of a process in which faultpoint is enabled, which placed points use."""


def start() -> None:
    """Enable faultpoint in this process: load and install its plugins, then obey its rules, so that a module a rule
    imports, such as the exception class of a call point, is imported through the installed import hook."""
    global RUNTIME
    try:
        settings = Settings()
        config = Config.read(settings.config)
        available = {point.name: point for point in entry_points(group=PLUGIN_GROUP)}
        plugins: dict[str, Plugin] = {name: available[name].load() for name in config.plugins}
        RUNTIME = Runtime(settings, config, plugins)
        for name, plugin in plugins.items():
            if plugin.install is not None:
                plugin.install(RUNTIME, config.options.get(name, {}))
        source = provided((plugin.source for plugin in plugins.values()), file_rule_source)(settings, config)
        if source is not None:
            RUNTIME.reload(source)
        if RUNTIME.sink is not None:
            atexit.register(RUNTIME.sink.flush)
        serve_in_background(RUNTIME, source)
        os.register_at_fork(after_in_child=functools.partial(restart_in_child, RUNTIME, source))
    except Exception as error:
        stop(error)


def serve_in_background(runtime: Runtime, source: RuleSource | None) -> None:
    """Poll the rules and write the observations from threads of their own, and write them on a stopping signal
    whose disposition is still the default."""
    if source is not None:
        threading.Thread(target=repeat, args=(POLL_INTERVAL_S, functools.partial(runtime.reload, source)),
                         name="faultpoint-rules", daemon=True).start()
    if runtime.sink is not None:
        threading.Thread(target=repeat, args=(runtime.sink.interval, runtime.sink.flush),
                         name="faultpoint-observations", daemon=True).start()
        for signum, disposition in DEFAULT_DISPOSITIONS.items():
            if signal.getsignal(signum) is disposition:
                signal.signal(signum, functools.partial(flush_then_resignal, runtime.sink))


def restart_in_child(runtime: Runtime, source: RuleSource | None) -> None:
    """Continue in a child forked from this process, as a gunicorn worker is, which has none of the parent's
    threads: with locks no parent thread holds, the sink as a process of its own, and the background work
    started again."""
    runtime.rules.lock = threading.Lock()
    if runtime.sink is not None:
        runtime.sink.forked()
    serve_in_background(runtime, source)
