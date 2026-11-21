import math
from collections import defaultdict
from enum import StrEnum
from statistics import fmean
from typing import Self

from pydantic import BaseModel
from scipy import stats

from faultpoint.observations import DetailItems, ObservationRecord
from faultpoint.rules import STRICT


class Selection(BaseModel):
    """One repetition of a group: the observations of an experiment, in one scope."""

    model_config = STRICT

    experiment: str
    scope: str

    @classmethod
    def parse(cls, text: str) -> Self:
        experiment, _, scope = text.partition("@")
        return cls(experiment=experiment, scope=scope)


class Metric(StrEnum):
    COUNT = "count"
    MEAN = "mean"
    """The total per execution, such as the mean latency."""


class Verdict(StrEnum):
    NEW = "new"
    INCREASE = "increase"


class Effect(BaseModel):
    """An outcome, with its detail, the treatment produced more of than the control."""

    model_config = STRICT

    point: str
    outcome: str
    detail: dict[str, str] = {}
    """Empty for outcomes recorded without detail, as observation records default it."""
    metric: Metric
    verdict: Verdict
    control: tuple[float, ...]
    treatment: tuple[float, ...]
    p_value: float | None


class Injection(BaseModel):
    """The executions a rule injected at, per treatment repetition."""

    model_config = STRICT

    rule: str
    point: str
    outcome: str
    counts: tuple[int, ...]


class Comparison(BaseModel):
    model_config = STRICT

    injections: tuple[Injection, ...]
    effects: tuple[Effect, ...]


def exceeds(control: list[float], treatment: list[float], alpha: float) -> tuple[bool, float | None]:
    """Whether the treatment is larger by a one-sided Welch t-test; two constant groups are
    compared directly and carry no p-value."""
    if len(set(control)) <= 1 and len(set(treatment)) <= 1:
        return sum(treatment) / len(treatment) > sum(control) / len(control), None
    p_value = float(stats.ttest_ind(treatment, control, equal_var=False,
                                    alternative="greater").pvalue)
    return not math.isnan(p_value) and p_value < alpha, p_value


def natural_tallies(records: list[ObservationRecord],
                    selection: Selection) -> dict[tuple[str, str, DetailItems], tuple[int, float]]:
    tallies: dict[tuple[str, str, DetailItems], tuple[int, float]] = defaultdict(lambda: (0, 0.0))
    for record in records:
        if (record.rule is None and record.experiment == selection.experiment
                and record.scope == selection.scope):
            key = (record.point, record.outcome, tuple(sorted(record.detail.items())))
            count, total = tallies[key]
            tallies[key] = (count + record.count, total + record.total)
    return tallies


def compare(records: list[ObservationRecord], control: list[Selection],
            treatment: list[Selection], alpha: float, min_mean_increase: float = 0.2) -> Comparison:
    """The outcomes a treatment adds to or increases over its control, and the injections that
    caused them; a mean counts only when it also grows by at least min_mean_increase of the
    control's, since a few repetitions make sub-millisecond shifts significant."""
    control_tallies = [natural_tallies(records, selection) for selection in control]
    treatment_tallies = [natural_tallies(records, selection) for selection in treatment]
    keys = sorted({key for tallies in control_tallies + treatment_tallies for key in tallies})
    effects: list[Effect] = []
    for point, outcome, detail in keys:
        key = (point, outcome, detail)
        control_counts = [float(tallies.get(key, (0, 0.0))[0]) for tallies in control_tallies]
        treatment_counts = [float(tallies.get(key, (0, 0.0))[0]) for tallies in treatment_tallies]
        if all(count == 0 for count in control_counts) and all(count > 0 for count in treatment_counts):
            effects.append(Effect(point=point, outcome=outcome, detail=dict(detail), metric=Metric.COUNT,
                                  verdict=Verdict.NEW, control=tuple(control_counts),
                                  treatment=tuple(treatment_counts), p_value=None))
            continue
        larger, p_value = exceeds(control_counts, treatment_counts, alpha)
        if larger:
            effects.append(Effect(point=point, outcome=outcome, detail=dict(detail), metric=Metric.COUNT,
                                  verdict=Verdict.INCREASE, control=tuple(control_counts),
                                  treatment=tuple(treatment_counts), p_value=p_value))
        control_means = [total / count for tallies in control_tallies
                         for count, total in [tallies.get(key, (0, 0.0))] if count]
        treatment_means = [total / count for tallies in treatment_tallies
                           for count, total in [tallies.get(key, (0, 0.0))] if count]
        if len(control_means) >= 2 and len(treatment_means) >= 2 and any(control_means + treatment_means):
            larger, p_value = exceeds(control_means, treatment_means, alpha)
            if larger and fmean(treatment_means) >= (1 + min_mean_increase) * fmean(control_means):
                effects.append(Effect(point=point, outcome=outcome, detail=dict(detail), metric=Metric.MEAN,
                                      verdict=Verdict.INCREASE, control=tuple(control_means),
                                      treatment=tuple(treatment_means), p_value=p_value))
    injected: dict[tuple[str, str, str], list[int]] = defaultdict(lambda: [0] * len(treatment))
    for index, selection in enumerate(treatment):
        for record in records:
            if (record.rule is not None and record.experiment == selection.experiment
                    and record.scope == selection.scope):
                injected[(record.rule, record.point, record.outcome)][index] += record.count
    injections = tuple(Injection(rule=rule, point=point, outcome=outcome, counts=tuple(counts))
                       for (rule, point, outcome), counts in sorted(injected.items()))
    return Comparison(injections=injections, effects=tuple(effects))
