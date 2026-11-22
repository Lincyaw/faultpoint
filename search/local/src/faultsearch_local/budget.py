from collections import Counter, defaultdict
from collections.abc import Callable
from enum import StrEnum
from statistics import fmean
from typing import Final

from faultsearch.allocation import AllocationSettings, Strategy
from faultsearch.catalog import FROZEN
from faultsearch.counterfactual import TreatmentRecord
from faultsearch.execution import RecordedExecutor
from faultsearch.facts import FactList, Facts, LoadVariants, PointInventory, SystemTopology
from faultsearch.graph import ComputeSettings, FactGraph
from faultsearch.plan import PlanSettings, PlanState, Refill, Stage, ValidationSettings, search
from faultsearch.validation import Selection, hop_checks, run_key
from pydantic import BaseModel

BUDGETS: Final = "plan-budgets"
"""The directory, in the full experiment's, of the offline comparison's trajectories."""
OFFLINE_VALIDATION: Final = ValidationSettings(runs=10, batch=5, per_group=3, single_scenario_cross_layer=0)
"""The validation the comparison simulates: the ranked runs of the full experiments' validations, without controls."""
TOP_RANKS: Final = 3
"""The rank among the stitched-only chains across layers a target must reach for the selection criterion."""


class Plan(StrEnum):
    """How an offline allocation spends its exploring budget and then its refill budget."""

    PHASED = "phased"
    """Coverage, round robin and weighting, then the counterparts in random order, round by round."""
    CANDIDATE = "phased-candidate"
    """Coverage, round robin and weighting, then the candidate phase."""
    RANDOM = "random"
    """Pairs drawn uniformly, then the counterparts in random order, round by round."""


class RunVerdict(StrEnum):
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    NEEDS_RUN = "needs-new-run"
    """The full experiment never ran this validation."""


class RankedRun(BaseModel):
    """A validation run the ranking picked, and what the full experiment's runs say of the chain that picked it."""

    model_config = FROZEN

    first: str
    workload: str
    chain: str
    verdict: RunVerdict


class Snapshot(BaseModel):
    """What an offline allocation found once it had spent a refill budget."""

    model_config = FROZEN

    refill: int
    """The refill budget."""
    explored: int
    """The injections the exploring stages asked for."""
    refilled: int
    """The refill injections asked for, those the records lack included."""
    unavailable: int
    """The injections the full experiment's runs lack, which would need new runs."""
    cross_layer: tuple[str, ...]
    """The stitched-only chains across layers that end in a failure the user sees, best ranked first."""
    verdicts: dict[str, bool]
    """Whether its run confirms each of those chains, for those whose run the full experiment ran."""
    runs: tuple[RankedRun, ...]


class Trajectory(BaseModel):
    """One offline allocation: a plan with an exploring budget and a seed, seen at every refill budget."""

    model_config = FROZEN

    plan: Plan
    explore: int
    seed: int
    snapshots: tuple[Snapshot, ...]


class Comparison:
    """A full experiment's facts, which an offline allocation draws its runs from, and what they say of every chain's
    path run."""

    def __init__(self, recorded: Facts, compute: ComputeSettings, allocation: AllocationSettings,
                 repetitions: int, pack_tenants: bool) -> None:
        self.recorded = recorded
        self.compute = compute
        self.allocation = allocation
        self.repetitions = repetitions
        self.pack_tenants = pack_tenants
        graph = FactGraph(recorded, compute)
        self.full = len(graph.assignments)
        self.path_records: dict[tuple[str, str], TreatmentRecord] = {
            (record.fault.key, record.workload): record for record in graph.judgement[0]}

    def started(self) -> FactList:
        """A new allocation's facts: the full experiment's topology and load variants."""
        log = FactList([])
        log.append(self.recorded.latest(SystemTopology).model_copy(update={"sequence": 1}))
        log.append(self.recorded.latest(LoadVariants).model_copy(update={"sequence": 2}))
        return log

    def inventory(self, labels: tuple[str, ...], sequence: int) -> PointInventory:
        return self.recorded.latest(PointInventory).model_copy(update={"sequence": sequence})

    def ranked_runs(self, log: FactList, state: PlanState, settings: PlanSettings) -> tuple[RankedRun, ...]:
        """The validation of an allocation's chains, run on a copy of its facts with the full experiment's path
        runs: every chain that picked a ranked run and its run's verdict, or that the full experiment never ran it."""
        copy = FactList(list(log.facts))
        validating = settings.model_copy(update={"validation": OFFLINE_VALIDATION})
        done = search(copy, state.model_copy(update={"stage": Stage.PATH_CONTROLS}), validating,
                      RecordedExecutor(self.recorded, copy), self.inventory, lambda saved: None)
        graph = FactGraph(copy.snapshot(), self.compute)
        verdicts = {validation.chain.key: validation.confirmed for validation in graph.judgement[2].validations
                    if validation.selection == Selection.CROSS_LAYER}
        scenarios = graph.variants.scenarios
        chains = {chain.key: chain for chain in (*graph.stitching.top, *graph.stitching.top_cross_layer)}
        return tuple(RankedRun(first=run_key(chains[key], scenarios)[0], workload=run_key(chains[key], scenarios)[1],
                               chain=key, verdict=RunVerdict.NEEDS_RUN if key not in verdicts
                               else RunVerdict.CONFIRMED if verdicts[key] else RunVerdict.REFUTED)
                     for key in done.picked)

    def snapshot(self, log: FactList, state: PlanState, settings: PlanSettings, unavailable: int) -> Snapshot:
        graph = FactGraph(log.snapshot(), self.compute)
        scenarios = graph.variants.scenarios
        across = [chain for chain in graph.stitching.top_cross_layer if chain.stitched_only]
        return Snapshot(refill=settings.refill_budget, explored=state.spent, refilled=state.refilled,
                        unavailable=unavailable, cross_layer=tuple(chain.key for chain in across),
                        verdicts={chain.key: all(hop.confirmed for hop in hop_checks(
                            chain, record, self.compute.min_count_increase)) and record.exercised
                            for chain in across if (record := self.path_records.get(run_key(chain, scenarios)))},
                        runs=self.ranked_runs(log, state, settings))

    def simulate(self, plan: Plan, explore: int, refills: list[int], seed: int) -> Trajectory:
        """One plan replayed on the full experiment's runs with an exploring budget and a seed, seen at every refill
        budget, the larger budgets continuing where the smaller stopped with a new round."""
        settings = PlanSettings(
            strategy=Strategy.RANDOM if plan == Plan.RANDOM else Strategy.PHASED,
            allocation=self.allocation.model_copy(update={"budget": explore, "seed": seed}),
            repetitions=self.repetitions, pack_tenants=self.pack_tenants,
            refill=Refill.CANDIDATE if plan == Plan.CANDIDATE else Refill.ROUNDS, refill_budget=0,
            validation=ValidationSettings(runs=0), compute=self.compute)
        log = self.started()
        executor = RecordedExecutor(self.recorded, log)
        state = PlanState.start(settings)
        snapshots = []
        for refill in sorted(refills):
            settings = settings.model_copy(update={"refill_budget": refill})
            state = search(log, state.model_copy(update={"stage": Stage.REFILL}) if state.stage == Stage.DONE else state,
                           settings, executor, self.inventory, lambda saved: None)
            snapshots.append(self.snapshot(log, state, settings, executor.unavailable))
        return Trajectory(plan=plan, explore=explore, seed=seed, snapshots=tuple(snapshots))


def target_rank(snapshot: Snapshot, target: Callable[[str], bool]) -> int | None:
    """The best rank of a target chain among the stitched-only chains across layers, from 1."""
    return next((rank for rank, key in enumerate(snapshot.cross_layer, 1) if target(key)), None)


def budget_table(trajectories: list[Trajectory], target: Callable[[str], bool], full: int) -> list[str]:
    """Per plan, exploring budget and refill budget, over the seeds: how often a target chain was stitched, its ranks,
    how often it ranked in the top ranks with its run confirming it, the ranked runs' verdicts and the injections,
    against the full experiment's."""
    cells: dict[tuple[Plan, int, int], list[Snapshot]] = defaultdict(list)
    for trajectory in trajectories:
        for found in trajectory.snapshots:
            cells[(trajectory.plan, trajectory.explore, found.refill)].append(found)
    lines = []
    for (plan, explore, refill), found in sorted(cells.items()):
        ranks = [target_rank(one, target) for one in found]
        selected = sum(rank is not None and rank <= TOP_RANKS and one.verdicts.get(one.cross_layer[rank - 1]) is True
                       for rank, one in zip(ranks, found, strict=True))
        verdicts = Counter(run.verdict for one in found for run in one.runs)
        injections = fmean(one.explored + one.refilled for one in found)
        lines.append(f"{plan} explore {explore} refill {refill}: stitched {sum(rank is not None for rank in ranks)}"
                     f"/{len(found)}, ranks {ranks}, top {TOP_RANKS} and confirmed {selected}/{len(found)}; runs "
                     f"{verdicts[RunVerdict.CONFIRMED]} confirmed, {verdicts[RunVerdict.REFUTED]} refuted, "
                     f"{verdicts[RunVerdict.NEEDS_RUN]} need new runs; injections {injections:.0f} "
                     f"({injections / full:.0%} of {full}), {fmean(one.unavailable for one in found):.0f} not recorded")
    return lines
