from collections import defaultdict
from enum import StrEnum
from pathlib import Path
from typing import Final, Self

from faultpoint.rules import Action
from faultpoint.tools.analysis import Effect, Metric, Verdict
from pydantic import BaseModel, JsonValue
from shop.workload import Scenarios

from faultsearch.allocation import Strategy
from faultsearch.catalog import DATA, FROZEN, Catalog, Fault, Layer, point_kind, point_layer, point_service
from faultsearch.counterfactual import TreatmentRecord

EFFECTS_FILE: Final = DATA / "effects.json"

type Condition = dict[str, JsonValue]


class EffectKey(BaseModel):
    model_config = FROZEN

    point: str
    outcome: str
    metric: Metric

    @property
    def key(self) -> str:
        return f"{self.point} {self.outcome} {self.metric}"

    @classmethod
    def of(cls, effect: Effect) -> Self:
        return cls(point=effect.point, outcome=effect.outcome, metric=effect.metric)


class EffectRule(BaseModel):
    """Which injectable faults an observed effect corresponds to; no faults when nothing injectable produces it."""

    model_config = FROZEN

    kind: str
    outcomes: tuple[str, ...]
    metric: Metric
    verdicts: tuple[Verdict, ...] = (Verdict.NEW, Verdict.INCREASE)
    faults: tuple[Action, ...]
    reason: str


class EffectMap(BaseModel):
    model_config = FROZEN

    entry_service: str
    """The service whose responses the user sees."""
    terminal_outcomes: tuple[str, ...]
    rules: tuple[EffectRule, ...]

    @classmethod
    def read(cls, path: Path = EFFECTS_FILE) -> Self:
        return cls.model_validate_json(path.read_text(encoding="utf-8"))

    def matching(self, effect: EffectKey, verdicts: set[Verdict]) -> list[EffectRule]:
        return [rule for rule in self.rules if rule.kind == point_kind(effect.point) and effect.outcome in rule.outcomes
                and rule.metric == effect.metric and verdicts & set(rule.verdicts)]

    def terminal(self, effect: EffectKey) -> bool:
        """Whether an effect is a failure the user sees: a non-2xx response of the entry service."""
        return (point_service(effect.point) == self.entry_service and point_kind(effect.point) == "rpc_server"
                and effect.outcome in self.terminal_outcomes)


class Counterpart(StrEnum):
    INJECTABLE = "injectable"
    """Faults of the catalog correspond to the effect."""
    OUTSIDE_CATALOG = "outside-catalog"
    """The effect map names actions, but the catalog does not try them at this point."""
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


def counterparts(effect: EffectKey, verdicts: set[Verdict], effects: EffectMap,
                 catalog: Catalog) -> tuple[Counterpart, tuple[Fault, ...]]:
    rules = effects.matching(effect, verdicts)
    templates = [template for rule in rules for template in rule.faults]
    faults = tuple(fault for fault in catalog.faults
                   if any(fault.instance_of(effect.point, template) for template in templates))
    if faults:
        return Counterpart.INJECTABLE, faults
    if templates:
        return Counterpart.OUTSIDE_CATALOG, ()
    return (Counterpart.NONE if rules else Counterpart.UNMAPPED), ()


def build_edges(records: list[TreatmentRecord], scenarios: Scenarios, effects: EffectMap, catalog: Catalog,
                upstream: frozenset[str], targets: dict[str, str]) -> list[Edge]:
    """Every (fault, effect) pair the exercised records show, over the scenarios each fault was tested in."""
    by_fault: dict[str, list[TreatmentRecord]] = defaultdict(list)
    for record in records:
        if record.exercised:
            by_fault[record.fault.key].append(record)
    edges = []
    for runs in by_fault.values():
        sightings: dict[str, list[Sighting]] = defaultdict(list)
        for run in runs:
            for effect in run.effects:
                sightings[EffectKey.of(effect).key].append(Sighting(scenario=run.workload, effect=effect))
        for held in sightings.values():
            effect = EffectKey.of(held[0].effect)
            held_in = [sighting.scenario for sighting in held]
            not_held = [run.workload for run in runs if run.workload not in held_in]
            counterpart, faults = counterparts(effect, {sighting.effect.verdict for sighting in held}, effects, catalog)
            edges.append(Edge(cause=runs[0].fault, effect=effect, held=tuple(held), not_held=tuple(not_held),
                              conditions=learn_conditions(held_in, not_held, scenarios), counterpart=counterpart,
                              counterparts=faults, terminal=effects.terminal(effect),
                              effect_layer=point_layer(effect.point, upstream),
                              acts_on=None if runs[0].fault.scoped else targets[point_service(runs[0].fault.point)]))
    return edges
