from collections import Counter, defaultdict
from enum import StrEnum
from statistics import fmean
from typing import Final

from faultpoint.observations import DetailItems
from faultpoint.tools.analysis import Effect, Metric, natural_tallies
from faultpoint.tools.analysis import Selection as Repetition
from pydantic import BaseModel

from faultsearch.catalog import FROZEN, Layer, point_service
from faultsearch.chains import Chain, Group, confidence
from faultsearch.counterfactual import (UNSCOPED, ControlRecord, EffectKey, NamedWorkload, Repetitions, Scenarios,
                                        TreatmentRecord, tenant_names)
from faultsearch.edges import Condition, Edge, holds
from faultsearch.evidence import ClassChecks, MappingCheck, step_classes

VALIDATION_PREFIX: Final = "validate."

type ObservationTallies = dict[tuple[str, str, DetailItems], tuple[int, float]]
type RunKey = tuple[str, str]
"""A validation run: the key of the first fault it injects and the name of the merged workload it runs in."""


class Selection(StrEnum):
    STITCHED_ONLY = "ranked-stitched-only"
    """Recorded by validations that chose chains one by one."""
    SINGLE_SCENARIO = "ranked-single-scenario"
    """Recorded by validations that chose chains one by one."""
    CROSS_LAYER = "ranked-cross-layer"
    """Stitched only, with hops in more than one layer, ending in a failure the user sees: the chain that picked its
    validation run."""
    SINGLE_SCENARIO_CROSS_LAYER = "ranked-single-scenario-cross-layer"
    """Shown end to end by one scenario, with hops in more than one layer, ending in a failure the user sees."""
    NAMED = "named"
    """Asked for by its key, outside the ranking."""
    ADJUDICATED = "adjudicated-by-run"
    """A kept chain no selection took whose first fault and merged workload a validation run had, checked against
    that run, since one run decides every chain it could check."""


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


def mapping_checks(validations: Validations) -> list[MappingCheck]:
    """For every validated hop whose effect appeared, whether the next hop's effect followed."""
    return [MappingCheck(effect=effect.key, counterpart=counterpart.key, consequence=consequence.key,
                         confirmed=validation.hops[index + 1].confirmed, chain=validation.chain.key,
                         workload=validation.workload.name,
                         classes=step_classes(effect, counterpart, point_service(consequence.point)))
            for validation in validations.validations if validation.record.exercised
            for index, (effect, counterpart, consequence) in enumerate(validation.chain.steps())
            if validation.hops[index].confirmed]


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


def chain_room(chain: Chain, workload: NamedWorkload, tallies: dict[str, list[ObservationTallies]],
               edges: dict[str, Edge], min_count_increase: float) -> ChainRoom:
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


def merged_workloads(chains: list[Chain], scenarios: Scenarios) -> list[NamedWorkload]:
    """The distinct workloads the chains' conditions merge into, in the chains' order."""
    return list({workload.name: workload for workload in (merged_workload(chain.condition, scenarios)
                                                          for chain in chains)}.values())


def headroom(chains: list[Chain], edges: list[Edge], scenarios: Scenarios, min_count_increase: float,
             controls: list[ControlRecord], repetitions: Repetitions) -> Headroom:
    """The headroom of every chain's count hops in its merged workload, given the controls of those workloads."""
    tallies: dict[str, dict[str, list[ObservationTallies]]] = {
        control.workload.name: {scope: [natural_tallies(repetitions.observations(label),
                                                        Repetition(experiment=label, scope=scope))
                                        for label in control.labels]
                                for scope in (UNSCOPED, tenant_names(control.workload.workload)[0])}
        for control in controls}
    by_key = {edge.key: edge for edge in edges}
    workloads = {chain.key: merged_workload(chain.condition, scenarios) for chain in chains}
    return Headroom(chains=tuple(chain_room(chain, workloads[chain.key], tallies[workloads[chain.key].name], by_key,
                                            min_count_increase) for chain in chains))


def run_key(chain: Chain, scenarios: Scenarios) -> RunKey:
    """The validation run that checks a chain: its first fault in the workload its conditions merge into."""
    return chain.hops[0].cause.key, merged_workload(chain.condition, scenarios).name


def chosen_runs(candidates: list[Chain], scenarios: Scenarios, checked: dict[str, ClassChecks], count: int,
                per_group: int, done: set[RunKey], picked: Counter[Group]) -> list[Chain]:
    """The chains that pick the next validation runs. A run is worth the summed chance of confirmation of the
    candidates it would check, since one run decides them all; the groups take turns, the group with the most valuable
    run first, each picking through its likeliest candidate its most valuable run not yet taken, at most per_group runs
    a group over all batches, so that one causal path does not take every run."""
    worth: dict[RunKey, float] = defaultdict(float)
    for chain in candidates:
        worth[run_key(chain, scenarios)] += confidence(chain.steps(), checked)
    best: dict[Group, dict[RunKey, Chain]] = defaultdict(dict)
    for chain in sorted(candidates, key=lambda chain: confidence(chain.steps(), checked), reverse=True):
        if run_key(chain, scenarios) not in done:
            best[chain.group].setdefault(run_key(chain, scenarios), chain)
    groups = sorted(best, key=lambda group: max(worth[key] for key in best[group]), reverse=True)
    queues = {group: sorted(best[group].items(), key=lambda item: worth[item[0]], reverse=True)[
        :max(0, per_group - picked[group])] for group in groups}
    unique: dict[RunKey, Chain] = {}
    for key, chain in (queues[group][turn] for turn in range(per_group) for group in groups
                       if turn < len(queues[group])):
        unique.setdefault(key, chain)
    return list(unique.values())[:count]


def adjudications(validations: Validations, kept: list[Chain], scenarios: Scenarios,
                  min_count_increase: float) -> tuple[Validation, ...]:
    """Every kept chain that no validation took and whose first fault and merged workload a validation run had,
    checked against that run's record."""
    runs = {(validation.record.fault.key, validation.workload.name): validation
            for validation in validations.validations}
    taken = {validation.chain.key for validation in validations.validations}
    return tuple(Validation(chain=chain, selection=Selection.ADJUDICATED, workload=run.workload, record=run.record,
                            hops=hop_checks(chain, run.record, min_count_increase))
                 for chain in kept if chain.key not in taken and (run := runs.get(run_key(chain, scenarios)))
                 is not None)


def hop_checks(chain: Chain, record: TreatmentRecord, min_count_increase: float) -> tuple[HopCheck, ...]:
    observed = {EffectKey.of(effect).key: effect for effect in record.effects if holds(effect, min_count_increase)}
    return tuple(HopCheck(hop=index, effect=hop.effect, confirmed=hop.effect.key in observed,
                          observed=observed.get(hop.effect.key)) for index, hop in enumerate(chain.hops))


class RunVerdict(StrEnum):
    """What the path run of a chain's first fault in its merged workload says of the chain."""

    CONFIRMED = "confirmed"
    """The first fault was injected in every repetition and every hop's effect appeared."""
    REFUTED = "refuted"
    NEEDS_RUN = "needs-new-run"
    """No such path run has run."""


def run_verdict(chain: Chain, path_records: dict[RunKey, TreatmentRecord], scenarios: Scenarios,
                min_count_increase: float) -> RunVerdict:
    """A chain judged by the path run that checks it, the path runs' records given by their run keys."""
    record = path_records.get(run_key(chain, scenarios))
    if record is None:
        return RunVerdict.NEEDS_RUN
    confirmed = record.exercised and all(hop.confirmed for hop in hop_checks(chain, record, min_count_increase))
    return RunVerdict.CONFIRMED if confirmed else RunVerdict.REFUTED
