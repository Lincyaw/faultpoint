import random
from collections import defaultdict
from enum import StrEnum
from functools import cached_property
from itertools import combinations
from statistics import fmean

import numpy as np
from pydantic import BaseModel, Field
from scipy.cluster.hierarchy import fcluster, linkage
from scipy.spatial.distance import squareform
from shop.workload import Scenarios

from faultsearch.catalog import FROZEN, Catalog, Fault
from faultsearch.counterfactual import EffectKey, NamedWorkload, Runner, TreatmentRecord


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


class Exploration:
    """One strategy's allocation in progress: the pairs it assigned and their records."""

    def __init__(self, runner: Runner, catalog: Catalog, scenarios: Scenarios, settings: AllocationSettings) -> None:
        self.runner = runner
        self.catalog = catalog
        self.settings = settings
        self.order = [scenario.name for scenario in scenarios.scenarios]
        self.workloads = {name: NamedWorkload(name=name, workload=scenarios.workload(name)) for name in self.order}
        self.rng = random.Random(settings.seed)
        self.assignments: list[Assignment] = []
        self.records: dict[tuple[str, str], TreatmentRecord] = {}

    def run(self, assignments: list[Assignment]) -> None:
        records = self.runner.treatments([(assignment.fault, self.workloads[assignment.scenario])
                                          for assignment in assignments])
        self.assignments += assignments
        self.records.update({(assignment.fault.key, assignment.scenario): record
                             for assignment, record in zip(assignments, records, strict=True)})

    def untested(self, fault: Fault, taken: set[tuple[str, str]]) -> list[str]:
        """The scenarios that execute a fault's point and that it was not assigned to, best covering first."""
        return [name for name in self.catalog.scenarios_executing(fault, self.order)
                if (fault.key, name) not in self.records and (fault.key, name) not in taken]

    def choose(self, members: list[str], phase: Phase, taken: set[tuple[str, str]]) -> list[Assignment]:
        """A random member of a cluster in a random scenario it was not assigned to; none when every member was."""
        candidates = [(key, self.untested(self.catalog.by_key[key], taken)) for key in members]
        candidates = [(key, scenarios) for key, scenarios in candidates if scenarios]
        if not candidates:
            return []
        key, scenarios = self.rng.choice(candidates)
        return [Assignment(fault=self.catalog.by_key[key], scenario=self.rng.choice(scenarios), phase=phase)]

    def runs(self) -> list[TreatmentRecord]:
        return [record for record in self.records.values() if record.exercised]

    def first_runs(self) -> dict[str, TreatmentRecord]:
        first: dict[str, TreatmentRecord] = {}
        for assignment in self.assignments:
            record = self.records[(assignment.fault.key, assignment.scenario)]
            if record.exercised:
                first.setdefault(assignment.fault.key, record)
        return first

    def members(self) -> dict[int, list[str]]:
        members: dict[int, list[str]] = defaultdict(list)
        for key, number in cluster_faults(self.first_runs(), self.settings.cluster_distance).items():
            members[number].append(key)
        return dict(members)

    def allocation(self, strategy: Strategy) -> Allocation:
        members = self.members()
        scores = cluster_similarities(members, self.runs())
        return Allocation(
            strategy=strategy, assignments=tuple(self.assignments),
            clusters=tuple(Cluster(number=number, members=tuple(keys), similarity=scores[number])
                           for number, keys in sorted(members.items())),
            unexercised=tuple(sorted({assignment.fault.key for assignment in self.assignments} - set(self.first_runs()))))


def round_robin(exploration: Exploration, members: dict[int, list[str]], budget: int) -> None:
    """Every cluster in turn gets one more injection: a random member in a scenario new to it."""
    spent = 0
    while spent < budget:
        batch: list[Assignment] = []
        for number in sorted(members):
            if spent + len(batch) < budget:
                batch += exploration.choose(members[number], Phase.ROUND_ROBIN, set())
        if not batch:
            return
        exploration.run(batch)
        spent += len(batch)


def weighted(exploration: Exploration, members: dict[int, list[str]], budget: int) -> None:
    """Injections drawn by cluster weight, max(epsilon, 1 - similarity), which favours clusters whose effects differ
    from one scenario to another, the sign of conditional causality."""
    settings = exploration.settings
    spent = 0
    while spent < budget:
        scores = cluster_similarities(members, exploration.runs())
        open_clusters = sorted(members)
        batch: list[Assignment] = []
        taken: set[tuple[str, str]] = set()
        while open_clusters and len(batch) < min(settings.batch, budget - spent):
            number = exploration.rng.choices(
                open_clusters, weights=[max(settings.epsilon, 1 - scores[number]) for number in open_clusters])[0]
            chosen = exploration.choose(members[number], Phase.WEIGHTED, taken)
            if not chosen:
                open_clusters.remove(number)
            batch += chosen
            taken |= {(assignment.fault.key, assignment.scenario) for assignment in chosen}
        if not batch:
            return
        exploration.run(batch)
        spent += len(batch)


def cover(exploration: Exploration) -> None:
    """Every fault of the catalog no assignment tried, once, where its point runs most."""
    assigned = {assignment.fault.key for assignment in exploration.assignments}
    exploration.run([Assignment(fault=fault, scenario=scenarios[0], phase=Phase.COVERAGE)
                     for fault in exploration.catalog.faults
                     if fault.key not in assigned and (scenarios := exploration.untested(fault, set()))])


def phased_allocation(exploration: Exploration) -> Allocation:
    """Phased budget allocation: every fault once where its point runs most, clustered into causally equivalent
    faults; then the clusters in turn; then the clusters by weight."""
    cover(exploration)
    remaining = exploration.settings.budget - len(exploration.assignments)
    members = exploration.members()
    round_robin(exploration, members, round(remaining * exploration.settings.round_robin_share))
    weighted(exploration, members, exploration.settings.budget - len(exploration.assignments))
    return exploration.allocation(Strategy.PHASED)


def extended_allocation(exploration: Exploration, strategy: Strategy, assignments: list[Assignment]) -> Allocation:
    """Given assignments, those an earlier allocation recorded among them, then every fault of the catalog they leave
    out once; the clusters are those of every fault's first run."""
    exploration.run(assignments)
    cover(exploration)
    return exploration.allocation(strategy)


def random_allocation(exploration: Exploration) -> Allocation:
    """The same budget spent on pairs drawn uniformly from every fault and every scenario that executes its point."""
    candidates = [(fault, name) for fault in exploration.catalog.faults
                  for name in exploration.catalog.scenarios_executing(fault, exploration.order)]
    chosen = exploration.rng.sample(candidates, min(exploration.settings.budget, len(candidates)))
    exploration.run([Assignment(fault=fault, scenario=name, phase=Phase.RANDOM) for fault, name in chosen])
    return exploration.allocation(Strategy.RANDOM)
