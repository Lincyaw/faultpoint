from collections import defaultdict
from enum import StrEnum
from typing import Final, Self

from faultpoint.tools.analysis import Effect
from pydantic import BaseModel
from shop.workload import Scenarios

from faultsearch.catalog import FROZEN
from faultsearch.chains import Chain, Stitching
from faultsearch.counterfactual import EffectKey, NamedWorkload, Runner, TreatmentRecord
from faultsearch.edges import Condition, holds

VALIDATION_PREFIX: Final = "validate."


class Selection(StrEnum):
    STITCHED_ONLY = "ranked-stitched-only"
    SINGLE_SCENARIO = "ranked-single-scenario"
    CROSS_LAYER = "ranked-cross-layer"
    """Stitched only, with hops in more than one layer, ending in a failure the user sees."""
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
    return NamedWorkload(name=f"{VALIDATION_PREFIX}{name or 'baseline'}",
                         workload=scenarios.baseline.with_changes(condition))


def selected(stitching: Stitching, stitched_only: int, single_scenario: int, cross_layer: int,
             named: list[str], validated: list[Chain]) -> list[tuple[Chain, Selection]]:
    """The best ranked chains that exist only by stitching, a few that one scenario showed end to end, the best
    stitched-only chains across layers not chosen already, and the chains named by their keys, which may also be
    chains validated before."""
    by_key = {chain.key: chain for chain in (*validated, *stitching.top, *stitching.top_cross_layer)}
    ranked = [chain for chain in stitching.top if chain.stitched_only][:stitched_only]
    chosen = {chain.key for chain in ranked}
    return ([(chain, Selection.STITCHED_ONLY) for chain in ranked]
            + [(chain, Selection.SINGLE_SCENARIO) for chain in stitching.top if not chain.stitched_only][:single_scenario]
            + [(chain, Selection.CROSS_LAYER) for chain in stitching.top_cross_layer
               if chain.stitched_only and chain.key not in chosen][:cross_layer]
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
