from collections import Counter, defaultdict
from enum import StrEnum
from statistics import fmean
from typing import Final, Self

from faultpoint.observations import DetailItems
from faultpoint.tools.analysis import Effect, Metric, natural_tallies
from faultpoint.tools.analysis import Selection as Repetition
from pydantic import BaseModel

from faultsearch.catalog import FROZEN, Layer
from faultsearch.chains import Chain, Stitching
from faultsearch.counterfactual import (EffectKey, NamedWorkload, Runner, Scenarios, TreatmentRecord,
                                        tenant_names)
from faultsearch.edges import Condition, Edge, holds

VALIDATION_PREFIX: Final = "validate."
UNSCOPED: Final = ""

type Tallies = dict[tuple[str, str, DetailItems], tuple[int, float]]


class Selection(StrEnum):
    STITCHED_ONLY = "ranked-stitched-only"
    SINGLE_SCENARIO = "ranked-single-scenario"
    CROSS_LAYER = "ranked-cross-layer"
    """Stitched only, with hops in more than one layer, ending in a failure the user sees."""
    SINGLE_SCENARIO_CROSS_LAYER = "ranked-single-scenario-cross-layer"
    """Shown end to end by one scenario, with hops in more than one layer, ending in a failure the user sees."""
    NAMED = "named"
    """Asked for by its key, outside the ranking."""


class HopCheck(BaseModel):
    model_config = FROZEN

    hop: int
    effect: EffectKey
    confirmed: bool
    observed: Effect | None
    """The comparison of the effect in the merged workload, absent when the effect did not appear."""


class Validation(BaseModel):
    """A chain checked end to end: only its first fault injected in the workload its conditions merge into."""

    model_config = FROZEN

    chain: Chain
    selection: Selection
    workload: NamedWorkload
    record: TreatmentRecord
    hops: tuple[HopCheck, ...]

    @property
    def confirmed(self) -> bool:
        return self.record.exercised and all(hop.confirmed for hop in self.hops)


class Validations(BaseModel):
    model_config = FROZEN

    validations: tuple[Validation, ...]


class MappingCheck(BaseModel):
    """Where a validated chain's effect appeared, whether the consequence the chain expected of the fault the effect
    was stitched to followed: a check of the effect map's correspondence, for that consequence, in that workload."""

    model_config = FROZEN

    effect: str
    counterpart: str
    consequence: str
    confirmed: bool
    chain: str
    workload: str


class MappingFeedback(BaseModel):
    model_config = FROZEN

    checks: tuple[MappingCheck, ...]

    def refuted(self) -> frozenset[tuple[str, str, str]]:
        """The (effect, counterpart, consequence) steps that validations refuted and never confirmed; a counterpart
        can carry one consequence of an effect and not another, as negating orders' retryable carries more retries
        but not retries that each reserve again."""
        seen: dict[tuple[str, str, str], set[bool]] = defaultdict(set)
        for check in self.checks:
            seen[(check.effect, check.counterpart, check.consequence)].add(check.confirmed)
        return frozenset(step for step, verdicts in seen.items() if verdicts == {False})

    def merged(self, checks: list[MappingCheck]) -> Self:
        """These checks with the new ones, a new check of the same chain in the same workload replacing the old."""
        identity = {(check.effect, check.counterpart, check.consequence, check.chain, check.workload): check
                    for check in (*self.checks, *checks)}
        return self.model_validate({"checks": tuple(identity.values())})


def mapping_checks(validations: Validations) -> list[MappingCheck]:
    """For every validated hop whose effect appeared, whether the next hop's effect followed."""
    return [MappingCheck(effect=validation.chain.hops[index].effect.key,
                         counterpart=validation.chain.hops[index + 1].cause.key,
                         consequence=validation.chain.hops[index + 1].effect.key,
                         confirmed=validation.hops[index + 1].confirmed, chain=validation.chain.key,
                         workload=validation.workload.name)
            for validation in validations.validations if validation.record.exercised
            for index in range(len(validation.chain.hops) - 1) if validation.hops[index].confirmed]


def merged_workload(condition: Condition, scenarios: Scenarios) -> NamedWorkload:
    name = "+".join(f"{parameter}={'-'.join(map(str, value)) if isinstance(value, list) else value}"
                    for parameter, value in sorted(condition.items()))
    return NamedWorkload(name=f"{VALIDATION_PREFIX}{name or 'baseline'}", workload={**scenarios.baseline, **condition})


class HopRoom(BaseModel):
    """Whether a count hop can rise visibly in its chain's merged workload: the level its cause drives the count to
    where its edge held, the highest over those scenarios of the lowest treatment count, against the counts of that
    workload's control, in the scope the effect is observed in."""

    model_config = FROZEN

    hop: int
    level: float
    control: tuple[float, ...]
    room: bool
    """No control repetition reaches the level, and the level is at least the smallest increase of the controls'
    mean that counts as an effect."""


class ChainRoom(BaseModel):
    model_config = FROZEN

    chain: str
    workload: str
    hops: tuple[HopRoom, ...]

    @property
    def room(self) -> bool:
        return all(hop.room for hop in self.hops)


class Headroom(BaseModel):
    """The headroom of the chains a validation chooses from, in their rank order."""

    model_config = FROZEN

    chains: tuple[ChainRoom, ...]


def chain_room(chain: Chain, workload: NamedWorkload, tallies: dict[str, list[Tallies]], edges: dict[str, Edge],
               min_count_increase: float) -> ChainRoom:
    """Whether every count hop of a chain has headroom in its merged workload; the effects of upstream components are
    observed outside any scope, the others in the treated tenant's."""
    hops = []
    for index, hop in enumerate(chain.hops):
        if hop.effect.metric == Metric.COUNT:
            key = (hop.effect.point, hop.effect.outcome, tuple(sorted(hop.effect.detail.items())))
            scope = UNSCOPED if hop.effect_layer == Layer.UPSTREAM else tenant_names(workload.workload)[0]
            control = tuple(float(counts.get(key, (0, 0.0))[0]) for counts in tallies[scope])
            edge = edges[f"[{hop.cause.key}] {hop.effect.key}"]
            level = max(min(sighting.effect.treatment) for sighting in edge.held)
            hops.append(HopRoom(hop=index, level=level, control=control,
                                room=max(control) < level and level >= (1 + min_count_increase) * fmean(control)))
    return ChainRoom(chain=chain.key, workload=workload.name, hops=tuple(hops))


def headroom(runner: Runner, chains: list[Chain], edges: list[Edge], scenarios: Scenarios,
             min_count_increase: float) -> Headroom:
    """The headroom of every chain's count hops in its merged workload, whose controls run first where missing."""
    workloads = {chain.key: merged_workload(chain.condition, scenarios) for chain in chains}
    tallies: dict[str, dict[str, list[Tallies]]] = {}
    for control in runner.controls(list({workload.name: workload for workload in workloads.values()}.values())):
        observations = {label: runner.observations(label) for label in control.labels}
        tallies[control.workload.name] = {
            scope: [natural_tallies(records, Repetition(experiment=label, scope=scope))
                    for label, records in observations.items()]
            for scope in (UNSCOPED, tenant_names(control.workload.workload)[0])}
    by_key = {edge.key: edge for edge in edges}
    return Headroom(chains=tuple(chain_room(chain, workloads[chain.key], tallies[workloads[chain.key].name], by_key,
                                            min_count_increase) for chain in chains))


def capped(chains: list[Chain], count: int, per_pair: int) -> list[Chain]:
    """The first count chains, at most per_pair of them with the same layer of the first fault and the same last
    effect, so that one hub does not take every pick."""
    taken: Counter[tuple[Layer, str]] = Counter()
    picks = []
    for chain in chains:
        pair = (chain.hops[0].cause.layer, chain.hops[-1].effect.key)
        if len(picks) < count and taken[pair] < per_pair:
            taken[pair] += 1
            picks.append(chain)
    return picks


def selected(stitching: Stitching, stitched_only: int, single_scenario: int, single_scenario_cross_layer: int,
             cross_layer: int, per_pair: int, named: list[str], validated: list[Chain],
             roomy: frozenset[str]) -> list[tuple[Chain, Selection]]:
    """Among the chains whose count hops all have headroom in their merged workloads, the best ranked that exist only
    by stitching, a few that one scenario showed end to end, of any layers and across layers, and the best
    stitched-only chains across layers not chosen already, at most per_pair of them alike; and the chains named by
    their keys, which may also be chains validated before."""
    by_key = {chain.key: chain for chain in (*validated, *stitching.top, *stitching.top_cross_layer)}
    ranked = [chain for chain in stitching.top if chain.stitched_only and chain.key in roomy][:stitched_only]
    chosen = {chain.key for chain in ranked}
    across = capped([chain for chain in stitching.top_cross_layer
                     if chain.stitched_only and chain.key not in chosen and chain.key in roomy], cross_layer, per_pair)
    return ([(chain, Selection.STITCHED_ONLY) for chain in ranked]
            + [(chain, Selection.SINGLE_SCENARIO) for chain in stitching.top
               if chain.shown and chain.key in roomy][:single_scenario]
            + [(chain, Selection.SINGLE_SCENARIO_CROSS_LAYER) for chain in stitching.top_cross_layer
               if chain.shown and chain.key in roomy][:single_scenario_cross_layer]
            + [(chain, Selection.CROSS_LAYER) for chain in across]
            + [(by_key[key], Selection.NAMED) for key in named])


def hop_checks(chain: Chain, record: TreatmentRecord, min_count_increase: float) -> tuple[HopCheck, ...]:
    observed = {EffectKey.of(effect).key: effect for effect in record.effects if holds(effect, min_count_increase)}
    return tuple(HopCheck(hop=index, effect=hop.effect, confirmed=hop.effect.key in observed,
                          observed=observed.get(hop.effect.key)) for index, hop in enumerate(chain.hops))


def validate(runner: Runner, chains: list[tuple[Chain, Selection]], scenarios: Scenarios,
             min_count_increase: float) -> Validations:
    workloads = [merged_workload(chain.condition, scenarios) for chain, _ in chains]
    records = runner.isolated_treatments([(chain.hops[0].cause, workload)
                                          for (chain, _), workload in zip(chains, workloads, strict=True)])
    return Validations(validations=tuple(
        Validation(chain=chain, selection=selection, workload=workload, record=record,
                   hops=hop_checks(chain, record, min_count_increase))
        for (chain, selection), workload, record in zip(chains, workloads, records, strict=True)))
