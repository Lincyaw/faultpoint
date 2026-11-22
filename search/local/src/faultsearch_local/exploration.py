import random

from faultsearch.allocation import (Allocation, AllocationSettings, Assignment, Phase, Strategy, allocation_of,
                                    cluster_members, cluster_similarities, first_runs)
from faultsearch.catalog import Catalog, Fault
from faultsearch.counterfactual import NamedWorkload, Scenarios, TreatmentRecord

from faultsearch_local.runner import Runner


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

    def tried(self) -> set[tuple[str, str]]:
        """The (fault, scenario) pairs the budget was spent on."""
        return set(self.records)

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

    def members(self) -> dict[int, list[str]]:
        return cluster_members(first_runs(self.assignments, self.records), self.settings.cluster_distance)

    def allocation(self, strategy: Strategy) -> Allocation:
        return allocation_of(strategy, self.assignments, self.records, self.settings.cluster_distance)


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
