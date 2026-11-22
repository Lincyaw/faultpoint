import random
from collections import Counter
from collections.abc import Callable
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, Field

from faultsearch.allocation import AllocationSettings, Assignment, Phase, Strategy, cluster_members, \
    cluster_similarities, first_runs
from faultsearch.catalog import FROZEN, Fault
from faultsearch.chains import Chain
from faultsearch.counterfactual import NamedWorkload, pack
from faultsearch.edges import counterpart_assignments
from faultsearch.execution import Executor, RunRequest
from faultsearch.facts import CONTROL_GROUP, FactList, Facts, LoadVariants, PathRequest, PointInventory, Purpose
from faultsearch.graph import ComputeSettings, FactGraph
from faultsearch.refill import candidate_batch, hypotheses
from faultsearch.validation import Selection, chosen_runs, merged_workload, merged_workloads, run_key

RANDOM_VERSION: Final = 3
"""The version of the state of Python's random generator, which a plan state keeps the numbers of."""
EVERY_CHAIN: Final = 10**6
"""Chains kept in full when the candidate phase continues every stitched chain."""

type Pair = tuple[str, str]
"""A fault's key and a workload's name: one injection of the budget."""


class Stage(StrEnum):
    CONTROLS = "controls"
    COVERAGE = "coverage"
    ROUND_ROBIN = "round-robin"
    WEIGHTED = "weighted"
    RANDOM = "random"
    REFILL = "refill"
    PATH_CONTROLS = "path-controls"
    VALIDATION = "validation"
    DONE = "done"


class Refill(StrEnum):
    """How a plan spends its refill budget on counterparts."""

    NONE = "none"
    ROUNDS = "rounds"
    """Every counterpart the edges need, in random order, round by round, as the complete command ran them."""
    CANDIDATE = "candidate"
    """The candidate phase: the counterparts that decide the hypothesised hops of the best candidate chains."""


class ValidationSettings(BaseModel):
    """How the ranked chains choose path runs: as many runs, chosen in batches of as many, at most as many a group,
    the best chains across layers one scenario showed as controls, and chains asked for by key."""

    model_config = FROZEN

    runs: int = 10
    batch: int = 5
    per_group: int = 3
    single_scenario_cross_layer: int = 3
    chains: tuple[str, ...] = ()


class PlanSettings(BaseModel):
    """What a plan follows from its start to its end."""

    model_config = FROZEN

    strategy: Strategy
    allocation: AllocationSettings
    repetitions: int = Field(ge=2)
    pack_tenants: bool
    refill: Refill
    refill_budget: int = Field(ge=0)
    validation: ValidationSettings
    compute: ComputeSettings


class PlanState(BaseModel):
    """Where a plan is: its stage, its random generator, the injections it asked for and what each stage spent, the
    clusters the round robin and the weighting share, and the path runs the validation asked for."""

    model_config = FROZEN

    stage: Stage = Stage.CONTROLS
    random: tuple[int, ...]
    """The numbers of the state of the random generator."""
    tried: tuple[Pair, ...] = ()
    """The injections of the load variants the plan asked for, in order, those no executor ran included."""
    spent: int = 0
    """The injections the exploring stages asked for."""
    members: dict[int, tuple[str, ...]] = {}
    """The clusters' faults the round robin and the weighting draw from, fixed when the round robin starts."""
    round_robin_budget: int = 0
    round_robin_spent: int = 0
    weighted_budget: int = 0
    weighted_spent: int = 0
    refilled: int = 0
    """The injections the refill stage asked for."""
    validated: int = 0
    """The ranked runs the validation went through, batch by batch."""
    asked: tuple[tuple[str, str], ...] = ()
    """The path runs the validation asked for: first fault and merged workload."""
    picked: tuple[str, ...] = ()
    """The chains that picked ranked runs."""

    @classmethod
    def start(cls, settings: PlanSettings) -> "PlanState":
        return cls(random=tuple(random.Random(settings.allocation.seed).getstate()[1]))

    def generator(self) -> random.Random:
        generator = random.Random()
        generator.setstate((RANDOM_VERSION, self.random, None))
        return generator


class PlanStep(BaseModel):
    """What a plan asks for next: the requests to run, or the point inventory its caller must write first, naming the
    load variants' control runs, and the state after it; a step with neither ends the plan."""

    model_config = FROZEN

    requests: tuple[RunRequest, ...] = ()
    inventory: tuple[str, ...] = ()
    state: PlanState

    @property
    def done(self) -> bool:
        return self.state.stage == Stage.DONE


class Planning:
    """One call of the plan: the facts so far, their graph and the generator, and the requests and state it builds."""

    def __init__(self, facts: Facts, state: PlanState, settings: PlanSettings) -> None:
        self.facts = facts
        self.state = state
        self.settings = settings
        self.graph = FactGraph(facts, settings.compute)
        self.scenarios = facts.latest(LoadVariants).scenarios
        self.order = [scenario.name for scenario in self.scenarios.scenarios]
        self.workloads = {name: NamedWorkload(name=name, workload=self.scenarios.workload(name)) for name in self.order}
        self.rng = state.generator()
        self.tried = set(state.tried)

    def assigned(self, assignments: list[Assignment]) -> list[RunRequest]:
        """Assignments as requests, packed into groups when the settings allow it, and recorded as tried."""
        pairs = [(assignment.fault, self.workloads[assignment.scenario]) for assignment in assignments]
        phases = {(assignment.fault.key, assignment.scenario): assignment.phase for assignment in assignments}
        groups = pack(pairs) if self.settings.pack_tenants else [
            group for fault, workload in pairs for group in pack([(fault, workload)])]
        self.tried |= set(phases)
        self.state = self.state.model_copy(update={"tried": (*self.state.tried, *phases)})
        return [RunRequest(workload=group.workload, faults=group.faults, purpose=Purpose.EDGE,
                           phases=tuple(phases[(fault.key, group.workload.name)] for fault in group.faults),
                           repetitions=self.settings.repetitions) for group in groups]

    def untested(self, fault: Fault, taken: set[Pair]) -> list[str]:
        """The scenarios that execute a fault's point and that it was not assigned to, best covering first."""
        return [name for name in self.graph.catalog.scenarios_executing(fault, self.order)
                if (fault.key, name) not in self.tried and (fault.key, name) not in taken]

    def choose(self, members: tuple[str, ...], phase: Phase, taken: set[Pair]) -> list[Assignment]:
        """A random member of a cluster in a random scenario it was not assigned to; none when every member was."""
        by_key = self.graph.catalog.by_key
        candidates = [(key, scenarios) for key in members if (scenarios := self.untested(by_key[key], taken))]
        if not candidates:
            return []
        key, scenarios = self.rng.choice(candidates)
        return [Assignment(fault=by_key[key], scenario=self.rng.choice(scenarios), phase=phase)]

    def controls(self, workloads: list[NamedWorkload], purpose: Purpose) -> list[RunRequest]:
        """The controls of the workloads the facts lack any control run of."""
        present = {(run.workload.name, run.index) for run in self.graph.runs if run.group == CONTROL_GROUP}
        return [RunRequest(workload=workload, purpose=purpose, repetitions=self.settings.repetitions)
                for workload in workloads
                if any((workload.name, index) not in present for index in range(self.settings.repetitions))]

    def leaked(self) -> list[RunRequest]:
        """The faults of packed groups that leaked into an untreated tenant and that never ran alone since."""
        records = self.graph.phased_records
        return [RunRequest(workload=group.workload, faults=(fault,), purpose=Purpose.EDGE, phases=(phase,),
                           repetitions=self.settings.repetitions)
                for group, members in self.graph.edge_groups
                for fault, phase in zip(group.faults, members[0].phases, strict=True)
                if (fault.key, group.workload.name) not in records]

    def variant_controls(self) -> list[RunRequest]:
        return self.controls(list(self.workloads.values()), Purpose.EDGE)

    def coverage(self) -> list[RunRequest]:
        """Every fault of the catalog no assignment tried, once, where its point runs most."""
        assigned = {key for key, _ in self.tried}
        batch = [Assignment(fault=fault, scenario=scenarios[0], phase=Phase.COVERAGE)
                 for fault in self.graph.catalog.faults
                 if fault.key not in assigned and (scenarios := self.untested(fault, set()))]
        self.state = self.state.model_copy(update={"spent": self.state.spent + len(batch)})
        return self.assigned(batch)

    def round_robin(self) -> list[RunRequest]:
        """Every cluster in turn gets one more injection: a random member in a scenario new to it; the clusters and
        the budget are fixed when the round robin starts."""
        if not self.state.members:
            members = cluster_members(first_runs(self.graph.assignments, self.graph.by_pair),
                                      self.settings.allocation.cluster_distance)
            remaining = self.settings.allocation.budget - len(self.graph.assignments)
            self.state = self.state.model_copy(update={
                "members": {number: tuple(keys) for number, keys in members.items()},
                "round_robin_budget": round(remaining * self.settings.allocation.round_robin_share)})
        batch: list[Assignment] = []
        for number in sorted(self.state.members):
            if self.state.round_robin_spent + len(batch) < self.state.round_robin_budget:
                batch += self.choose(self.state.members[number], Phase.ROUND_ROBIN, set())
        self.state = self.state.model_copy(update={"round_robin_spent": self.state.round_robin_spent + len(batch),
                                                   "spent": self.state.spent + len(batch)})
        return self.assigned(batch)

    def weighted(self) -> list[RunRequest]:
        """Injections drawn by cluster weight, max(epsilon, 1 - similarity), which favours clusters whose effects
        differ from one scenario to another, the sign of conditional causality; the budget is what the round robin
        left when the weighting starts."""
        settings = self.settings.allocation
        if self.state.weighted_spent == 0 and not self.state.weighted_budget:
            self.state = self.state.model_copy(update={"weighted_budget": settings.budget - len(self.graph.assignments)})
        budget = self.state.weighted_budget - self.state.weighted_spent
        members = {number: list(keys) for number, keys in self.state.members.items()}
        scores = cluster_similarities(members, [record for record in self.graph.records if record.exercised])
        open_clusters = sorted(members)
        batch: list[Assignment] = []
        taken: set[Pair] = set()
        while budget > 0 and open_clusters and len(batch) < min(settings.batch, budget):
            number = self.rng.choices(
                open_clusters, weights=[max(settings.epsilon, 1 - scores[number]) for number in open_clusters])[0]
            chosen = self.choose(self.state.members[number], Phase.WEIGHTED, taken)
            if not chosen:
                open_clusters.remove(number)
            batch += chosen
            taken |= {(assignment.fault.key, assignment.scenario) for assignment in chosen}
        self.state = self.state.model_copy(update={"weighted_spent": self.state.weighted_spent + len(batch),
                                                   "spent": self.state.spent + len(batch)})
        return self.assigned(batch)

    def random_pairs(self) -> list[RunRequest]:
        """The budget spent at once on pairs drawn uniformly from every fault and every scenario that executes its
        point."""
        if self.state.spent:
            return []
        catalog = self.graph.catalog
        candidates = [(fault, name) for fault in catalog.faults for name in catalog.scenarios_executing(fault, self.order)]
        chosen = self.rng.sample(candidates, min(self.settings.allocation.budget, len(candidates)))
        self.state = self.state.model_copy(update={"spent": len(chosen)})
        return self.assigned([Assignment(fault=fault, scenario=name, phase=Phase.RANDOM) for fault, name in chosen])

    def refill(self) -> list[RunRequest]:
        """The next refill batch within the refill budget: a round of every needed counterpart in random order, or a
        batch of the candidate phase."""
        budget = self.settings.refill_budget - self.state.refilled
        if budget <= 0 or self.settings.refill == Refill.NONE:
            return []
        if self.settings.refill == Refill.ROUNDS:
            needed = counterpart_assignments(self.graph.edges, self.tried, self.graph.catalog)
            self.rng.shuffle(needed)
            batch = needed[:budget]
        else:
            graph = FactGraph(self.facts, self.settings.compute.model_copy(update={"kept": EVERY_CHAIN}))
            found = hypotheses(graph.allocation, graph.edges, graph.stitching, graph.by_pair, graph.catalog,
                               self.order, self.tried, graph.stitcher)
            batch = candidate_batch(found, graph.stitching, min(self.settings.allocation.batch, budget))
        self.state = self.state.model_copy(update={"refilled": self.state.refilled + len(batch)})
        return self.assigned(batch)

    def kept(self) -> list[Chain]:
        stitching = self.graph.stitching
        order = {key: rank for rank, key in enumerate(stitching.keys)}
        return sorted({chain.key: chain for chain in (*stitching.top, *stitching.top_cross_layer)}.values(),
                      key=lambda chain: order[chain.key])

    def path_controls(self) -> list[RunRequest]:
        """The controls of the merged workloads the kept chains' conditions give, which headroom compares with."""
        return self.controls(merged_workloads(self.kept(), self.scenarios), Purpose.PATH)

    def validation(self) -> list[RunRequest]:
        """The next batch of path runs: the runs the candidates' summed chances favour, every group taking turns and
        at most so many runs a group, the checks so far updating the chances; the first batch adds the best chains
        across layers one scenario showed and the chains asked for by key."""
        settings = self.settings.validation
        kept = self.kept()
        by_key = {chain.key: chain for chain in kept}
        _, room, _ = self.graph.judgement
        roomy = {chain_room.chain for chain_room in room.chains if chain_room.room}
        across = [chain for chain in kept if chain.crosses_layers and chain.terminal and chain.key in roomy]
        candidates = [chain for chain in across if chain.stitched_only and not chain.contradicted]
        asked: list[tuple[Chain, Selection]] = []
        while not asked and self.state.validated < settings.runs:
            start = self.state.validated
            picks = chosen_runs(candidates, self.scenarios, self.graph.feedback.class_checks(),
                                min(settings.batch, settings.runs - start), settings.per_group, set(self.state.asked),
                                Counter(by_key[key].group for key in self.state.picked))
            besides = [] if start else (
                [(chain, Selection.SINGLE_SCENARIO_CROSS_LAYER) for chain in across
                 if chain.shown][:settings.single_scenario_cross_layer]
                + [(by_key[key], Selection.NAMED) for key in settings.chains])
            asked = [(pick, Selection.CROSS_LAYER) for pick in picks] + besides
            self.state = self.state.model_copy(update={
                "validated": start + settings.batch, "picked": (*self.state.picked, *(pick.key for pick in picks)),
                "asked": tuple(dict.fromkeys((*self.state.asked, *(run_key(chain, self.scenarios)
                                                                    for chain, _ in asked))))})
        runs: dict[tuple[str, str], tuple[Chain, list[PathRequest]]] = {}
        for chain, selection in asked:
            runs.setdefault(run_key(chain, self.scenarios), (chain, []))[1].append(
                PathRequest(chain=chain.key, selection=selection))
        return [RunRequest(workload=merged_workload(chain.condition, self.scenarios), faults=(chain.hops[0].cause,),
                           purpose=Purpose.PATH, requests=tuple(requests), repetitions=self.settings.repetitions)
                for chain, requests in runs.values()]


def next_stage(stage: Stage, settings: PlanSettings) -> Stage:
    """The stage after one that has nothing more to ask for."""
    validating = settings.validation.runs > 0 or bool(settings.validation.chains)
    return {Stage.CONTROLS: Stage.COVERAGE if settings.strategy == Strategy.PHASED else Stage.RANDOM,
            Stage.COVERAGE: Stage.ROUND_ROBIN, Stage.ROUND_ROBIN: Stage.WEIGHTED, Stage.WEIGHTED: Stage.REFILL,
            Stage.RANDOM: Stage.REFILL, Stage.REFILL: Stage.PATH_CONTROLS if validating else Stage.DONE,
            Stage.PATH_CONTROLS: Stage.VALIDATION, Stage.VALIDATION: Stage.DONE}[stage]


STAGES: Final[dict[Stage, Callable[[Planning], list[RunRequest]]]] = {
    Stage.CONTROLS: Planning.variant_controls, Stage.COVERAGE: Planning.coverage,
    Stage.ROUND_ROBIN: Planning.round_robin, Stage.WEIGHTED: Planning.weighted, Stage.RANDOM: Planning.random_pairs,
    Stage.REFILL: Planning.refill, Stage.PATH_CONTROLS: Planning.path_controls, Stage.VALIDATION: Planning.validation}


def plan(facts: Facts, state: PlanState, settings: PlanSettings) -> PlanStep:
    """The next requests the facts so far call for, moving on through the stages that have nothing more to ask; a
    packed group that leaked has its faults run alone first, and the load variants' controls are followed by the
    point inventory the caller writes."""
    stage = state.stage
    while stage != Stage.DONE:
        planning = Planning(facts, state.model_copy(update={"stage": stage}), settings)
        if stage not in (Stage.CONTROLS, Stage.COVERAGE, Stage.RANDOM) and (rerun := planning.leaked()):
            return PlanStep(requests=tuple(rerun), state=planning.state)
        requests = STAGES[stage](planning)
        if requests:
            return PlanStep(requests=tuple(requests), state=planning.state.model_copy(
                update={"random": tuple(planning.rng.getstate()[1])}))
        state = planning.state.model_copy(update={"random": tuple(planning.rng.getstate()[1])})
        stage = next_stage(stage, settings)
        if stage in (Stage.COVERAGE, Stage.RANDOM) and not facts.holds(PointInventory):
            return PlanStep(inventory=tuple(sorted(run.label for run in planning.graph.runs
                                                   if run.group == CONTROL_GROUP)),
                            state=state.model_copy(update={"stage": stage}))
    return PlanStep(state=state.model_copy(update={"stage": Stage.DONE}))


def search(log: FactList, state: PlanState, settings: PlanSettings, executor: Executor,
           inventory: Callable[[tuple[str, ...], int], PointInventory],
           saved: Callable[[PlanState], None]) -> PlanState:
    """Plan and run until the plan ends: every step's requests run and written to the log by the executor, the point
    inventory written when the plan asks for it, and every new state saved."""
    while state.stage != Stage.DONE:
        step = plan(log.snapshot(), state, settings)
        if step.inventory:
            log.append(inventory(step.inventory, log.next_sequence()))
        executor.run(list(step.requests))
        state = step.state
        saved(state)
    return state
