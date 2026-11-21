from collections import defaultdict
from enum import StrEnum
from statistics import fmean
from typing import Final, Self

from faultpoint.tools.analysis import Metric
from pydantic import BaseModel

from faultsearch.catalog import FROZEN, Fault, point_kind, point_service
from faultsearch.counterfactual import EffectKey


class Substitution(StrEnum):
    """How closely a counterpart reproduces the effect it stands for."""

    EXACT = "exact"
    APPROXIMATE = "approximate"
    """A delay standing for a mean that grew, which reproduces the slowness but not what caused it."""


def step_classes(effect: EffectKey, counterpart: Fault, consequence: EffectKey) -> tuple[str, ...]:
    """The classes a step from an effect through its counterpart to a consequence belongs to, through which the checks
    of one step inform the estimate of another: the counterpart's action at its kind of point, the point the effect is
    at, the services of the counterpart and of the consequence, and whether the counterpart only approximates the
    effect."""
    substitution = Substitution.APPROXIMATE if effect.metric == Metric.MEAN else Substitution.EXACT
    return (f"action {counterpart.action.kind} at {point_kind(counterpart.point)}", f"effect at {effect.point}",
            f"services {point_service(counterpart.point)} > {point_service(consequence.point)}",
            f"substitution {substitution}")


class ClassChecks(BaseModel):
    """How many steps of one class validations confirmed and refuted."""

    model_config = FROZEN

    confirmed: int
    refuted: int

    def probability(self) -> float:
        """The mean of a Beta(1, 1) prior updated with the checks, so that an unchecked class is an even chance and a
        few checks move it only part of the way."""
        return (self.confirmed + 1) / (self.confirmed + self.refuted + 2)


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
    classes: tuple[str, ...] = ()
    """The step's classes; checks recorded before steps were classed have none."""


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

    def class_checks(self) -> dict[str, ClassChecks]:
        """The checks of every class, each step counted once per workload however many chains took it, since one run
        decides it for all of them."""
        steps = {(check.effect, check.counterpart, check.consequence, check.workload): check for check in self.checks}
        counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for check in steps.values():
            for name in check.classes:
                counts[name][0 if check.confirmed else 1] += 1
        return {name: ClassChecks(confirmed=confirmed, refuted=refuted)
                for name, (confirmed, refuted) in counts.items()}


UNCHECKED: Final = ClassChecks(confirmed=0, refuted=0)


def step_probability(classes: tuple[str, ...], checked: dict[str, ClassChecks]) -> float:
    """The chance that a step holds, the mean over its classes of their estimates: each class is another view of the
    same substitution, and the mean keeps one sparse class from deciding alone."""
    return fmean(checked.get(name, UNCHECKED).probability() for name in classes)
