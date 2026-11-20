from enum import StrEnum
from typing import Final

from faultpoint.tools.analysis import Effect
from pydantic import BaseModel
from shop.workload import Scenarios

from faultsearch.catalog import FROZEN
from faultsearch.chains import Chain, Stitching
from faultsearch.edges import Condition, EffectKey
from faultsearch.counterfactual import NamedWorkload, Runner, TreatmentRecord

VALIDATION_PREFIX: Final = "validate."


class Selection(StrEnum):
    STITCHED_ONLY = "ranked-stitched-only"
    SINGLE_SCENARIO = "ranked-single-scenario"
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


def merged_workload(condition: Condition, scenarios: Scenarios) -> NamedWorkload:
    name = "+".join(f"{parameter}={'-'.join(map(str, value)) if isinstance(value, list) else value}"
                    for parameter, value in sorted(condition.items()))
    return NamedWorkload(name=f"{VALIDATION_PREFIX}{name or 'baseline'}",
                         workload=scenarios.baseline.with_changes(condition))


def selected(stitching: Stitching, stitched_only: int, single_scenario: int,
             named: list[str]) -> list[tuple[Chain, Selection]]:
    """The best ranked chains that exist only by stitching, a few that one scenario showed end to end, and the
    chains named by their keys."""
    by_key = {chain.key: chain for chain in stitching.top}
    return ([(chain, Selection.STITCHED_ONLY) for chain in stitching.top if chain.stitched_only][:stitched_only]
            + [(chain, Selection.SINGLE_SCENARIO) for chain in stitching.top if not chain.stitched_only][:single_scenario]
            + [(by_key[key], Selection.NAMED) for key in named])


def hop_checks(chain: Chain, record: TreatmentRecord) -> tuple[HopCheck, ...]:
    observed = {EffectKey.of(effect).key: effect for effect in record.effects}
    return tuple(HopCheck(hop=index, effect=hop.effect, confirmed=hop.effect.key in observed,
                          observed=observed.get(hop.effect.key)) for index, hop in enumerate(chain.hops))


def validate(runner: Runner, chains: list[tuple[Chain, Selection]], scenarios: Scenarios) -> Validations:
    workloads = [merged_workload(chain.condition, scenarios) for chain, _ in chains]
    records = runner.isolated_treatments([(chain.hops[0].cause, workload)
                                          for (chain, _), workload in zip(chains, workloads, strict=True)])
    return Validations(validations=tuple(
        Validation(chain=chain, selection=selection, workload=workload, record=record, hops=hop_checks(chain, record))
        for (chain, selection), workload, record in zip(chains, workloads, records, strict=True)))
