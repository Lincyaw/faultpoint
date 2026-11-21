import json
from collections import defaultdict
from enum import StrEnum
from pathlib import Path
from statistics import fmean
from typing import Final, Self
from urllib.parse import urlsplit

from faultpoint.actions import ActionKind
from faultpoint.placement import Manifest
from faultpoint.rules import Action
from faultpoint.tools.analysis import Effect, Metric, Verdict
from faultpoint.tools.kinds import KindTable
from pydantic import BaseModel, JsonValue

from faultsearch.allocation import Assignment, Phase, Strategy
from faultsearch.catalog import (DATA, FROZEN, RPC_CLIENT, RPC_SERVER, Catalog, Fault, Layer, implements, point_kind,
                                 point_layer, point_scoped, point_service, point_symbol)
from faultsearch.counterfactual import EffectKey, Load, Scenarios, TreatmentRecord

EFFECTS_FILE: Final = DATA / "effects.json"
WAIT: Final = "ms"
"""The action parameter of how long a fail waits or a delay lasts."""
WAIT_DIGITS: Final = 2
"""The significant digits of a counterpart's time, so that near times share one fault."""
COUNT_SLACK: Final = 1.0
"""The executions per repetition two runs may differ by however few there are, below which a fraction says nothing."""
ABSENT: Final = Load(count=0, mean=0)
STATUS: Final = "status"
"""The action parameter of an exact status code: a number in a rule, a string in a detail."""
ERROR: Final = "error"
"""The detail key of an error's name."""

type Condition = dict[str, JsonValue]
type DetailValues = dict[str, tuple[str, ...]]
"""For every detail key named, the values a detail may have there."""


def shows(detail: dict[str, str], required: DetailValues) -> bool:
    return all(detail.get(name) in values for name, values in required.items())


def peer_point(client: str, services: dict[int, str]) -> str:
    """The server point a client point calls: the service listening on the locator's port, at the same method and
    path."""
    method, target = client.split(":", 2)[2].split(" ", 1)
    address = urlsplit(f"//{target}")
    return f"{services[address.port]}:{RPC_SERVER}:{method} {address.path}"


class Registration(StrEnum):
    REGISTERED = "registered"
    """The effect's error is a name its service's build registers, as the service's manifest lists them."""
    UNREGISTERED = "unregistered"
    """The effect's error is a name its service's build does not register."""


class PeerEffect(BaseModel):
    """An effect the server point a client point called must show in every run where the client effect held."""

    model_config = FROZEN

    outcomes: tuple[str, ...]
    details: DetailValues = {}


class EffectRule(BaseModel):
    """Which injectable faults an observed effect corresponds to; no faults when nothing injectable produces it."""

    model_config = FROZEN

    kind: str
    outcomes: tuple[str, ...]
    metric: Metric
    verdicts: tuple[Verdict, ...] = (Verdict.NEW, Verdict.INCREASE)
    layers: tuple[Layer, ...] = tuple(Layer)
    """The layers of the effect's point the rule covers."""
    languages: tuple[str, ...] | None = None
    """The languages of the points the rule covers, as the manifests listing them name them; every point when absent,
    and no point that no manifest lists otherwise."""
    functions: tuple[str, ...] | None = None
    """The functions whose native function points the rule covers; every point when absent."""
    details: DetailValues = {}
    """The detail values the effect must show."""
    excluded_details: DetailValues = {}
    """The detail values the effect must not show; a key the detail lacks excludes nothing, since it is unknown."""
    registration: Registration | None = None
    """Whether the effect's error must be one its service's build registers, or one it does not; the rule then covers
    only effects whose detail names an error."""
    parameters: dict[str, str] = {}
    """Action parameters the effect's detail gives, by the detail key that gives each; the rule covers only effects
    whose detail has those keys."""
    peer: PeerEffect | None = None
    faults: tuple[Action, ...]
    reason: str

    def covers_manifest(self, effect: EffectKey, manifest: Manifest | None) -> bool:
        """Whether the rule covers an effect at a point this manifest lists, none for a point no manifest lists: by
        the manifest's language and by whether its build registers the effect's error."""
        return ((self.languages is None or (manifest is not None and manifest.language in self.languages))
                and (self.registration is None
                     or (manifest is not None and ERROR in effect.detail
                         and (effect.detail[ERROR] in manifest.errors)
                         == (self.registration == Registration.REGISTERED))))

    def covers(self, effect: EffectKey, verdicts: set[Verdict], layer: Layer, manifest: Manifest | None,
               peer_effects: list[EffectKey]) -> bool:
        """Whether the rule covers an effect that held with these verdicts, at a point this manifest lists, beside
        these effects of the called server point."""
        return (self.kind == point_kind(effect.point) and effect.outcome in self.outcomes
                and self.metric == effect.metric and bool(verdicts & set(self.verdicts)) and layer in self.layers
                and self.covers_manifest(effect, manifest)
                and (self.functions is None or point_symbol(effect.point) in self.functions)
                and shows(effect.detail, self.details)
                and not any(effect.detail.get(name) in values for name, values in self.excluded_details.items())
                and set(self.parameters.values()) <= effect.detail.keys()
                and (self.peer is None
                     or any(peer.outcome in self.peer.outcomes and shows(peer.detail, self.peer.details)
                            for peer in peer_effects)))

    def actions(self, effect: EffectKey) -> list[Action]:
        """The rule's faults with the parameters the effect's detail gives."""
        given = {name: int(effect.detail[key]) if name == STATUS else effect.detail[key]
                 for name, key in self.parameters.items()}
        return [Action.model_validate({**template.model_dump(), **given}) for template in self.faults]


class NamedError(BaseModel):
    """An error as an observation names it, with why the effect map treats it apart."""

    model_config = FROZEN

    name: str
    reason: str


class EffectMap(BaseModel):
    model_config = FROZEN

    entry_service: str
    """The service whose responses the user sees, which the explored system names."""
    terminal_outcomes: tuple[str, ...]
    injected_errors: tuple[NamedError, ...] = ()
    """Errors only an SDK's injection gives. Recorded maps from before these names were listed list none."""
    caller_left_errors: tuple[NamedError, ...] = ()
    """Errors a service's work gets because its caller left, which no fault reproduces. Recorded maps from before
    these names were listed list none."""
    rules: tuple[EffectRule, ...]

    @classmethod
    def read(cls, entry_service: str, path: Path = EFFECTS_FILE) -> Self:
        """The effect map of the file, which holds what does not depend on the system, for a system's entry service."""
        return cls.model_validate({**json.loads(path.read_text(encoding="utf-8")), "entry_service": entry_service})

    def terminal(self, effect: EffectKey) -> bool:
        """Whether an effect is a failure the user sees: a non-2xx response of the entry service."""
        return (point_service(effect.point) == self.entry_service and point_kind(effect.point) == RPC_SERVER
                and effect.outcome in self.terminal_outcomes)

    def injected(self, effect: EffectKey) -> bool:
        """Whether an effect names an error only an injection gives, so that only a run injecting the fault behind it
        shows it."""
        return effect.detail.get(ERROR) in {error.name for error in self.injected_errors}

    def caller_left(self, effect: EffectKey) -> bool:
        """Whether an effect names an error a service's work gets because its caller left."""
        return effect.detail.get(ERROR) in {error.name for error in self.caller_left_errors}


class Counterpart(StrEnum):
    INJECTABLE = "injectable"
    """Faults of the catalog correspond to the effect."""
    OUTSIDE_CATALOG = "outside-catalog"
    """Faults correspond to the effect, some of them actions the catalog does not try at this point, such as a status
    or an error type a detail gives; the counterpart phase injects them."""
    NONE = "none"
    """The effect map says no action produces the effect."""
    UNMAPPED = "unmapped"
    """No rule of the effect map covers the effect."""


class Sighting(BaseModel):
    """An edge holding in one scenario: the comparison that showed it."""

    model_config = FROZEN

    scenario: str
    effect: Effect


class Edge(BaseModel):
    """A fault and an effect its injection caused, with the scenarios it held in, those tested where it did not,
    and the conditions learned from them."""

    model_config = FROZEN

    cause: Fault
    effect: EffectKey
    held: tuple[Sighting, ...]
    not_held: tuple[str, ...]
    conditions: tuple[Condition, ...]
    """Alternative sets of workload parameter values, each sufficient as far as the scenarios tested tell."""
    counterpart: Counterpart
    counterparts: tuple[Fault, ...]
    terminal: bool
    effect_layer: Layer
    acts_on: str | None = None
    """For a fault no rule can scope, the container or process it reaches the whole of."""
    injected: bool = False
    """Whether the effect names an error only an injection gives, so that the edge can start a chain but not continue
    one: a counterpart stands in for a natural effect, which never names that error."""
    mismatched: tuple[str, ...] = ()
    """The counterparts whose substitute runs behaved unlike this edge's natural run where callers see the effect's
    service, in every scenario both ran in, which no chain continues the edge with."""

    @property
    def held_in(self) -> frozenset[str]:
        return frozenset(sighting.scenario for sighting in self.held)

    @property
    def key(self) -> str:
        return f"[{self.cause.key}] {self.effect.key}"


class EdgeSet(BaseModel):
    model_config = FROZEN

    strategy: Strategy
    edges: tuple[Edge, ...]


def learn_conditions(held: list[str], not_held: list[str], scenarios: Scenarios) -> tuple[Condition, ...]:
    """The fewest parameter values shared by the scenarios an edge held in that set apart every scenario tested where
    it did not, and the baseline unless it held there; when no such values exist, each held scenario's changes."""
    values = {name: scenarios.workload(name) for name in (*held, *not_held)}
    baseline = scenarios.baseline
    shared = {name: value for name, value in values[held[0]].items()
              if all(values[scenario][name] == value for scenario in held)}
    opponents = [values[name] for name in not_held]
    if all(values[name] != baseline for name in held):
        opponents.append(baseline)
    condition: Condition = {}
    while opponents:
        separated = {name: [opponent for opponent in opponents if opponent[name] != value]
                     for name, value in shared.items() if name not in condition}
        best = max(separated, key=lambda name: len(separated[name]), default=None)
        if best is None or not separated[best]:
            return tuple(scenarios.named(name).changes for name in held)
        condition[best] = shared[best]
        opponents = [opponent for opponent in opponents if opponent not in separated[best]]
    return (condition,)


def holds(effect: Effect, min_count_increase: float) -> bool:
    """Whether an effect counts: a count that grew must grow by at least min_count_increase of the control's, since
    what runs outside any scope, such as an upstream component's background work, grows with a run's length."""
    return (effect.metric != Metric.COUNT or effect.verdict != Verdict.INCREASE
            or fmean(effect.treatment) >= (1 + min_count_increase) * fmean(effect.control))


def peer_effects(effect: EffectKey, runs: list[dict[str, Effect]], services: dict[int, str]) -> list[EffectKey]:
    """For a client point's effect, the effects of the server point it called that every run where it held showed."""
    if point_kind(effect.point) != RPC_CLIENT:
        return []
    peer = peer_point(effect.point, services)
    return [EffectKey.of(found) for key, found in runs[0].items()
            if found.point == peer and all(key in run for run in runs)]


def timed(action: Action, effect: EffectKey, layer: Layer, elapsed: float, increase: float) -> Action:
    """A counterpart's action with the time of the effect it stands for, so that its timing is faithful too: a fail
    waits as long as the natural failure took, and a delay for a slower mean adds the increase seen; a kernel point
    keeps the action as it is, since kernel points carry no elapsed time."""
    wait = (elapsed if action.kind == ActionKind.FAIL and effect.metric == Metric.COUNT
            else increase if action.kind == ActionKind.DELAY and effect.metric == Metric.MEAN else 0.0)
    if layer == Layer.UPSTREAM or wait < 1:
        return action
    return Action.model_validate({**action.model_dump(), WAIT: int(float(f"{wait:.{WAIT_DIGITS}g}"))})


def counterparts(effect: EffectKey, verdicts: set[Verdict], layer: Layer, manifest: Manifest | None,
                 peer_effects: list[EffectKey], effects: EffectMap, catalog: Catalog, kinds: KindTable,
                 elapsed: float, increase: float) -> tuple[Counterpart, tuple[Fault, ...]]:
    """The faults that, injected at an effect's point, produce the effect: the catalog's instances of every action
    the effect map names for it, timed as the effect, and the point implements, or the action itself where the
    catalog has none; none for an effect of a caller leaving."""
    if effects.caller_left(effect):
        return Counterpart.NONE, ()
    rules = [rule for rule in effects.rules if rule.covers(effect, verdicts, layer, manifest, peer_effects)]
    found = [([fault for fault in catalog.faults if fault.instance_of(effect.point, action)], action)
             for rule in rules for action in (timed(template, effect, layer, elapsed, increase)
                                              for template in rule.actions(effect))
             if implements(catalog.narrower, effect.point, action)]
    faults = {fault.key: fault for instances, action in found
              for fault in instances or [Fault(point=effect.point, action=action, layer=layer,
                                               scoped=point_scoped(effect.point, layer, kinds))]}
    if not rules:
        return Counterpart.UNMAPPED, ()
    if not found:
        return Counterpart.NONE, ()
    return (Counterpart.INJECTABLE if all(instances for instances, _ in found) else Counterpart.OUTSIDE_CATALOG,
            tuple(faults.values()))


def effect_time(held_runs: list[TreatmentRecord], held: list[Sighting], key: str,
                effect: EffectKey) -> tuple[float, float]:
    """How long the natural executions behind an effect took where it held, and for a slower mean how much it grew."""
    times = [run.elapsed[key] for run in held_runs if key in run.elapsed]
    increase = fmean(fmean(sighting.effect.treatment) - fmean(sighting.effect.control) for sighting in held) \
        if effect.metric == Metric.MEAN else 0.0
    return (fmean(times) if times else 0.0), increase


def behaves_alike(natural: TreatmentRecord, substitute: TreatmentRecord, service: str, services: dict[int, str],
                  min_count_increase: float, min_mean_increase: float) -> bool:
    """Whether a substitute run behaves as the natural run it stands for where callers see it: at the server points of
    the effect's service and at the client points that call them, every outcome within the smallest change that
    counts as an effect, in executions per repetition and in their mean."""
    points = {point for point in (*natural.boundary, *substitute.boundary)
              if (point_kind(point) == RPC_SERVER and point_service(point) == service)
              or (point_kind(point) == RPC_CLIENT and point_service(peer_point(point, services)) == service)}
    seen_points = {point: (natural.boundary.get(point, {}), substitute.boundary.get(point, {})) for point in points}
    loads = [(seen.get(outcome, ABSENT), stand.get(outcome, ABSENT))
             for seen, stand in seen_points.values() for outcome in {*seen, *stand}]
    return all(abs(seen.count - stand.count) <= max(COUNT_SLACK, min_count_increase * seen.count)
               and (not seen.count or not stand.count or abs(seen.mean - stand.mean) <= min_mean_increase * seen.mean)
               for seen, stand in loads)


def mismatched_counterparts(cause: Fault, effect: EffectKey, held_in: list[str], faults: tuple[Fault, ...],
                            runs: dict[tuple[str, str], TreatmentRecord], services: dict[int, str],
                            min_count_increase: float, min_mean_increase: float) -> tuple[str, ...]:
    """The counterparts whose substitute runs behaved unlike the natural run in every scenario where the edge held and
    both ran, which no chain continues the edge with; a counterpart no such scenario ran is not judged."""
    return tuple(fault.key for fault in faults if (checks := [
        behaves_alike(runs[(cause.key, scenario)], runs[(fault.key, scenario)], point_service(effect.point), services,
                      min_count_increase, min_mean_increase)
        for scenario in held_in if (fault.key, scenario) in runs]) and not any(checks))


def build_edges(records: list[TreatmentRecord], scenarios: Scenarios, effects: EffectMap, catalog: Catalog,
                kinds: KindTable, upstream: frozenset[str], targets: dict[str, str], services: dict[int, str],
                manifests: dict[str, Manifest], min_count_increase: float, min_mean_increase: float) -> list[Edge]:
    """Every (fault, effect) pair the exercised records show, over the scenarios each fault was tested in."""
    by_fault: dict[str, list[TreatmentRecord]] = defaultdict(list)
    for record in records:
        if record.exercised:
            by_fault[record.fault.key].append(record)
    by_run = {(record.fault.key, record.workload): record for runs in by_fault.values() for record in runs}
    edges = []
    for runs in by_fault.values():
        shown = {run.workload: {EffectKey.of(effect).key: effect for effect in run.effects
                                if holds(effect, min_count_increase)} for run in runs}
        for key in dict.fromkeys(key for in_run in shown.values() for key in in_run):
            held = [Sighting(scenario=name, effect=in_run[key]) for name, in_run in shown.items() if key in in_run]
            effect = EffectKey.of(held[0].effect)
            layer = point_layer(effect.point, upstream)
            held_in = [sighting.scenario for sighting in held]
            not_held = [run.workload for run in runs if run.workload not in held_in]
            elapsed, increase = effect_time([run for run in runs if run.workload in held_in], held, key, effect)
            counterpart, faults = counterparts(effect, {sighting.effect.verdict for sighting in held}, layer,
                                               manifests.get(effect.point),
                                               peer_effects(effect, [shown[name] for name in held_in], services),
                                               effects, catalog, kinds, elapsed, increase)
            edges.append(Edge(cause=runs[0].fault, effect=effect, held=tuple(held), not_held=tuple(not_held),
                              conditions=learn_conditions(held_in, not_held, scenarios), counterpart=counterpart,
                              counterparts=faults, terminal=effects.terminal(effect), effect_layer=layer,
                              injected=effects.injected(effect),
                              mismatched=mismatched_counterparts(runs[0].fault, effect, held_in, faults, by_run,
                                                                 services, min_count_increase, min_mean_increase),
                              acts_on=None if runs[0].fault.scoped else targets[point_service(runs[0].fault.point)]))
    return edges


def counterpart_assignments(edges: list[Edge], assigned: set[str]) -> list[Assignment]:
    """The faults no assignment tried that correspond to an effect a chain could continue from, each in the scenarios
    where the effect appeared."""
    return list({(fault.key, scenario): Assignment(fault=fault, scenario=scenario, phase=Phase.COUNTERPART)
                 for edge in edges if not edge.terminal
                 for fault in edge.counterparts if fault.key not in assigned
                 for scenario in sorted(edge.held_in)}.values())
