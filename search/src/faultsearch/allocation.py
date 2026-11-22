from collections import defaultdict
from enum import StrEnum
from functools import cached_property
from itertools import combinations
from statistics import fmean

import numpy as np
from pydantic import BaseModel, Field
from scipy.cluster.hierarchy import fcluster, linkage
from scipy.spatial.distance import squareform

from faultsearch.catalog import FROZEN, Fault
from faultsearch.counterfactual import EffectKey, TreatmentRecord


class Strategy(StrEnum):
    PHASED = "phased"
    RANDOM = "random"


class Phase(StrEnum):
    COVERAGE = "coverage"
    ROUND_ROBIN = "round-robin"
    WEIGHTED = "weighted"
    RANDOM = "random"
    COUNTERPART = "counterpart"
    """A fault no assignment tried that the effect map names for an effect, injected where the effect appeared."""
    CANDIDATE = "candidate"
    """A counterpart injected to decide a hypothesised hop of one of the best candidate chains."""


class AllocationSettings(BaseModel):
    model_config = FROZEN

    budget: int = Field(ge=1)
    """The injections, (fault, scenario) pairs, a strategy may run, the coverage phase included."""
    seed: int
    round_robin_share: float = Field(ge=0, le=1)
    """The share of the budget left after the coverage phase that the round-robin phase spends."""
    cluster_distance: float = Field(gt=0)
    """The cosine distance under which faults join one causally equivalent cluster."""
    epsilon: float = Field(gt=0)
    batch: int = Field(ge=1)
    """The injections the weighted phase chooses before it recomputes the clusters' weights."""


class Assignment(BaseModel):
    model_config = FROZEN

    fault: Fault
    scenario: str
    phase: Phase


class Cluster(BaseModel):
    model_config = FROZEN

    number: int
    members: tuple[str, ...]
    similarity: float
    """The mean pairwise cosine similarity of the effect vectors of every run of the members."""


class Allocation(BaseModel):
    model_config = FROZEN

    strategy: Strategy
    assignments: tuple[Assignment, ...]
    clusters: tuple[Cluster, ...]
    unexercised: tuple[str, ...]
    """The faults whose injection never triggered in their first scenario."""

    @cached_property
    def cluster_of(self) -> dict[str, Cluster]:
        return {member: cluster for cluster in self.clusters for member in cluster.members}


def effect_keys(record: TreatmentRecord) -> set[str]:
    return {EffectKey.of(effect).key for effect in record.effects}


def weighted_vectors(effect_sets: list[set[str]]) -> np.ndarray:
    """Indicator vectors over every effect the sets hold, weighted by inverse document frequency."""
    vocabulary = sorted(set().union(*effect_sets))
    present = np.array([[effect in effects for effect in vocabulary] for effects in effect_sets],
                       dtype=float).reshape(len(effect_sets), len(vocabulary))
    return present * np.log(len(effect_sets) / present.sum(axis=0))


def similarities(vectors: np.ndarray) -> np.ndarray:
    """Pairwise cosine similarity, where two runs without effects are alike and unlike every run with some."""
    norms = np.linalg.norm(vectors, axis=1)
    empty = norms == 0
    units = vectors / np.where(empty, 1.0, norms)[:, None]
    result = units @ units.T
    result[np.ix_(empty, empty)] = 1.0
    return result


def cluster_faults(first_runs: dict[str, TreatmentRecord], distance: float) -> dict[str, int]:
    """Faults clustered hierarchically by the cosine distance of their first runs' effect vectors."""
    keys = sorted(first_runs)
    if len(keys) < 2:
        return {key: 1 for key in keys}
    dissimilarity = np.clip(1 - similarities(weighted_vectors([effect_keys(first_runs[key]) for key in keys])), 0, 2)
    np.fill_diagonal(dissimilarity, 0)
    numbers = fcluster(linkage(squareform(dissimilarity, checks=False), method="average"), t=distance,
                       criterion="distance")
    return dict(zip(keys, (int(number) for number in numbers), strict=True))


def cluster_similarities(members: dict[int, list[str]], runs: list[TreatmentRecord]) -> dict[int, float]:
    """Every cluster's similarity over the runs of its members, a single run counting as fully similar."""
    similarity = similarities(weighted_vectors([effect_keys(run) for run in runs]))
    scores = {}
    for number, keys in members.items():
        rows = [index for index, run in enumerate(runs) if run.fault.key in keys]
        scores[number] = fmean(float(similarity[left, right]) for left, right in combinations(rows, 2)) \
            if len(rows) > 1 else 1.0
    return scores


def first_runs(assignments: list[Assignment], records: dict[tuple[str, str], TreatmentRecord]) -> dict[str, TreatmentRecord]:
    """Every fault's first exercised run, in the order of the assignments."""
    first: dict[str, TreatmentRecord] = {}
    for assignment in assignments:
        record = records[(assignment.fault.key, assignment.scenario)]
        if record.exercised:
            first.setdefault(assignment.fault.key, record)
    return first


def cluster_members(first: dict[str, TreatmentRecord], distance: float) -> dict[int, list[str]]:
    members: dict[int, list[str]] = defaultdict(list)
    for key, number in cluster_faults(first, distance).items():
        members[number].append(key)
    return dict(members)


def allocation_of(strategy: Strategy, assignments: list[Assignment], records: dict[tuple[str, str], TreatmentRecord],
                  distance: float) -> Allocation:
    """Assignments with the clusters of their faults' first runs and the similarity of every cluster over all the
    exercised runs, in the order the assignments ran."""
    first = first_runs(assignments, records)
    members = cluster_members(first, distance)
    runs = [record for pair in dict.fromkeys((assignment.fault.key, assignment.scenario) for assignment in assignments)
            if (record := records[pair]).exercised]
    scores = cluster_similarities(members, runs)
    return Allocation(
        strategy=strategy, assignments=tuple(assignments),
        clusters=tuple(Cluster(number=number, members=tuple(keys), similarity=scores[number])
                       for number, keys in sorted(members.items())),
        unexercised=tuple(sorted({assignment.fault.key for assignment in assignments} - set(first))))
