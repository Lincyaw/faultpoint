from collections import defaultdict
from enum import StrEnum
from pathlib import Path
from statistics import fmean
from typing import Final, Self
from urllib.parse import urlsplit

from faultpoint.placement import Manifest
from faultpoint.rules import Action
from faultpoint.tools.analysis import Effect, Metric, Verdict
from faultpoint.tools.kinds import KindTable
from pydantic import BaseModel, JsonValue
from shop.workload import Scenarios

from faultsearch.allocation import Assignment, Phase, Strategy
from faultsearch.catalog import (DATA, FROZEN, Catalog, Fault, Layer, point_kind, point_layer, point_scoped,
                                 point_service)
from faultsearch.counterfactual import EffectKey, TreatmentRecord

EFFECTS_FILE: Final = DATA / "effects.json"
RPC_CLIENT: Final = "rpc_client"
RPC_SERVER: Final = "rpc_server"
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
    details: DetailValues = {}
    """The detail values the effect must show."""
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
                and self.covers_manifest(effect, manifest) and shows(effect.detail, self.details)
                and set(self.parameters.values()) <= effect.detail.keys()
                and (self.peer is None
                     or any(peer.outcome in self.peer.outcomes and shows(peer.detail, self.peer.details)
                            for peer in peer_effects)))

    def actions(self, effect: EffectKey) -> list[Action]:
        """The rule's faults with the parameters the effect's detail gives."""
        given = {name: int(effect.detail[key]) if name == STATUS else effect.detail[key]
                 for name, key in self.parameters.items()}
        return [Action.model_validate({**template.model_dump(), **given}) for template in self.faults]


class EffectMap(BaseModel):
    model_config = FROZEN

    entry_service: str
    """The service whose responses the user sees."""
    terminal_outcomes: tuple[str, ...]
    rules: tuple[EffectRule, ...]

    @classmethod
    def read(cls, path: Path = EFFECTS_FILE) -> Self:
        return cls.model_validate_json(path.read_text(encoding="utf-8"))

    def terminal(self, effect: EffectKey) -> bool:
        """Whether an effect is a failure the user sees: a non-2xx response of the entry service."""
        return (point_service(effect.point) == self.entry_service and point_kind(effect.point) == RPC_SERVER
                and effect.outcome in self.terminal_outcomes)


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
    values = {name: scenarios.workload(name).model_dump(mode="json") for name in (*held, *not_held)}
    baseline = scenarios.baseline.model_dump(mode="json")
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


def counterparts(effect: EffectKey, verdicts: set[Verdict], layer: Layer, manifest: Manifest | None,
                 peer_effects: list[EffectKey], effects: EffectMap, catalog: Catalog,
                 kinds: KindTable) -> tuple[Counterpart, tuple[Fault, ...]]:
    """The faults that, injected at an effect's point, produce the effect: the catalog's instances of every action
    the effect map names for it, or the action itself where the catalog has none."""
    rules = [rule for rule in effects.rules if rule.covers(effect, verdicts, layer, manifest, peer_effects)]
    found = [([fault for fault in catalog.faults if fault.instance_of(effect.point, action)], action)
             for rule in rules for action in rule.actions(effect)]
    faults = {fault.key: fault for instances, action in found
              for fault in instances or [Fault(point=effect.point, action=action, layer=layer,
                                               scoped=point_scoped(effect.point, layer, kinds))]}
    if not rules:
        return Counterpart.UNMAPPED, ()
    if not found:
        return Counterpart.NONE, ()
    return (Counterpart.INJECTABLE if all(instances for instances, _ in found) else Counterpart.OUTSIDE_CATALOG,
            tuple(faults.values()))


def build_edges(records: list[TreatmentRecord], scenarios: Scenarios, effects: EffectMap, catalog: Catalog,
                kinds: KindTable, upstream: frozenset[str], targets: dict[str, str], services: dict[int, str],
                manifests: dict[str, Manifest], min_count_increase: float) -> list[Edge]:
    """Every (fault, effect) pair the exercised records show, over the scenarios each fault was tested in."""
    by_fault: dict[str, list[TreatmentRecord]] = defaultdict(list)
    for record in records:
        if record.exercised:
            by_fault[record.fault.key].append(record)
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
            counterpart, faults = counterparts(effect, {sighting.effect.verdict for sighting in held}, layer,
                                               manifests.get(effect.point),
                                               peer_effects(effect, [shown[name] for name in held_in], services),
                                               effects, catalog, kinds)
            edges.append(Edge(cause=runs[0].fault, effect=effect, held=tuple(held), not_held=tuple(not_held),
                              conditions=learn_conditions(held_in, not_held, scenarios), counterpart=counterpart,
                              counterparts=faults, terminal=effects.terminal(effect), effect_layer=layer,
                              acts_on=None if runs[0].fault.scoped else targets[point_service(runs[0].fault.point)]))
    return edges


def counterpart_assignments(edges: list[Edge], assigned: set[str]) -> list[Assignment]:
    """The faults no assignment tried that correspond to an effect a chain could continue from, each in the scenarios
    where the effect appeared."""
    return list({(fault.key, scenario): Assignment(fault=fault, scenario=scenario, phase=Phase.COUNTERPART)
                 for edge in edges if not edge.terminal
                 for fault in edge.counterparts if fault.key not in assigned
                 for scenario in sorted(edge.held_in)}.values())
