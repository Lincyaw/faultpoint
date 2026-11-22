from collections import Counter, defaultdict
from collections.abc import Callable
from enum import StrEnum
from statistics import fmean
from typing import Final

from faultsearch.allocation import Allocation, AllocationSettings, Assignment, Strategy
from faultsearch.catalog import FROZEN, Catalog
from faultsearch.chains import Chain, Stitcher, Stitching
from faultsearch.counterfactual import Scenarios
from faultsearch.edges import Edge
from faultsearch.evidence import MappingFeedback
from faultsearch.validation import (Selection, Validation, Validations, adjudications, chosen_runs, headroom,
                                    hop_checks, mapping_checks, merged_workload, merged_workloads, run_key)
from pydantic import BaseModel

from faultsearch_local.exploration import Exploration, phased_allocation, random_allocation
from faultsearch_local.refill import candidate_phase, counterpart_rounds, stitched
from faultsearch_local.runner import Runner
from faultsearch_local.store import CONTROLS

BUDGETS: Final = "budgets"
"""The directory, in the full experiment's, of the offline comparison's trajectories."""
RANKED_RUNS: Final = 10
RUN_BATCH: Final = 5
RUNS_PER_GROUP: Final = 3
"""The validation the comparison simulates: as many ranked runs, chosen in batches of as many, at most as many a
group, as the validations of the full experiments ran."""
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


class RecordedExploration(Exploration):
    """An exploration that takes its treatments from a full exploration's records and runs none: a pair the records
    lack is charged to the budget and stays untried."""

    def __init__(self, runner: Runner, catalog: Catalog, scenarios: Scenarios, settings: AllocationSettings) -> None:
        super().__init__(runner, catalog, scenarios, settings)
        self.unavailable: set[tuple[str, str]] = set()

    def run(self, assignments: list[Assignment]) -> None:
        missing = {(fault.key, workload.name) for fault, workload in self.runner.missing(
            [(assignment.fault, self.workloads[assignment.scenario]) for assignment in assignments])}
        self.unavailable |= missing
        super().run([assignment for assignment in assignments
                     if (assignment.fault.key, assignment.scenario) not in missing])

    def tried(self) -> set[tuple[str, str]]:
        return super().tried() | self.unavailable


class RunVerdict(StrEnum):
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    NEEDS_RUN = "needs-new-run"
    """The full experiment never ran this validation."""


class RankedRun(BaseModel):
    """A validation run the ranking picked, and what the full experiment's records say of the chain that picked it."""

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
    """The injections the exploring phases spent."""
    refilled: int
    """The refill injections charged, those the records lack included."""
    unavailable: int
    """The injections the full records lack, which would need new runs."""
    cross_layer: tuple[str, ...]
    """The stitched-only chains across layers that end in a failure the user sees, best ranked first."""
    verdicts: dict[str, bool]
    """Whether its run confirms each of those chains, for those whose run the full experiment validated."""
    runs: tuple[RankedRun, ...]


class Trajectory(BaseModel):
    """One offline allocation: a plan with an exploring budget and a seed, seen at every refill budget."""

    model_config = FROZEN

    plan: Plan
    explore: int
    seed: int
    snapshots: tuple[Snapshot, ...]


def recorded_runs(chains: list[Chain], runner: Runner, scenarios: Scenarios,
                  min_count_increase: float) -> dict[str, Validation]:
    """Every chain's check against its validation run, for the chains whose run the full experiment recorded."""
    runs = {chain.key: (chain, [(chain.hops[0].cause, merged_workload(chain.condition, scenarios))])
            for chain in chains}
    records = {key: runner.recorded(pairs)[0] for key, (_, pairs) in runs.items() if not runner.missing(pairs)}
    return {key: Validation(chain=runs[key][0], selection=Selection.CROSS_LAYER, workload=runs[key][1][0][1],
                            record=record, hops=hop_checks(runs[key][0], record, min_count_increase))
            for key, record in records.items()}


def ranked_runs(stitching: Stitching, edges: list[Edge], runner: Runner, scenarios: Scenarios) -> tuple[RankedRun, ...]:
    """The validation the validate command would run, decided from the full experiment's validation runs alone: the
    candidates with headroom that no natural witness contradicts pick runs in batches, and the checks of the runs the
    records hold update the chances that rank the next batch."""
    order = {key: rank for rank, key in enumerate(stitching.keys)}
    kept = sorted({chain.key: chain for chain in (*stitching.top, *stitching.top_cross_layer)}.values(),
                  key=lambda chain: order[chain.key])
    workloads = merged_workloads(kept, scenarios)
    missing = sorted(workload.name for workload in workloads if not runner.store.has(CONTROLS, f"{workload.name}.json"))
    if missing:
        raise RuntimeError(f"an offline comparison runs nothing, and these merged workloads have no controls: {missing}")
    roomy = {room.chain for room in headroom(kept, edges, scenarios, stitching.min_count_increase,
                                             runner.controls(workloads), runner).chains if room.room}
    candidates = [chain for chain in kept if chain.crosses_layers and chain.terminal and chain.key in roomy
                  and chain.stitched_only and not chain.contradicted]
    validations: list[Validation] = []
    feedback = MappingFeedback(checks=())
    picked: list[Chain] = []
    runs: list[RankedRun] = []
    for start in range(0, RANKED_RUNS, RUN_BATCH):
        picks = chosen_runs(candidates, scenarios, feedback.class_checks(), min(RUN_BATCH, RANKED_RUNS - start),
                            RUNS_PER_GROUP, {run_key(chain, scenarios) for chain in picked},
                            Counter(chain.group for chain in picked))
        picked += picks
        chosen = list(recorded_runs(picks, runner, scenarios, stitching.min_count_increase).values())
        decided = adjudications(Validations(validations=(*validations, *chosen)), kept, scenarios,
                                stitching.min_count_increase)
        validations += [*chosen, *decided]
        feedback = feedback.merged(mapping_checks(Validations(validations=(*chosen, *decided))))
        verdicts = {validation.chain.key: validation.confirmed for validation in chosen}
        runs += [RankedRun(first=pick.hops[0].cause.key, workload=merged_workload(pick.condition, scenarios).name,
                           chain=pick.key, verdict=RunVerdict.NEEDS_RUN if pick.key not in verdicts
                           else RunVerdict.CONFIRMED if verdicts[pick.key] else RunVerdict.REFUTED)
                 for pick in picks]
    return tuple(runs)


def snapshot(exploration: RecordedExploration, strategy: Strategy, refill: int, explored: int, refilled: int,
             stitcher: Stitcher) -> Snapshot:
    _, edges, stitching = stitched(exploration, strategy, stitcher)
    runner = exploration.runner
    across = [chain for chain in stitching.top_cross_layer if chain.stitched_only]
    checks = recorded_runs(across, runner, stitcher.scenarios, stitching.min_count_increase)
    return Snapshot(refill=refill, explored=explored, refilled=refilled, unavailable=len(exploration.unavailable),
                    cross_layer=tuple(chain.key for chain in across),
                    verdicts={key: validation.confirmed for key, validation in checks.items()},
                    runs=ranked_runs(stitching, edges, runner, stitcher.scenarios))


def simulate(plan: Plan, explore: int, refills: list[int], seed: int, runner: Runner, settings: AllocationSettings,
             stitcher: Stitcher) -> Trajectory:
    """One plan replayed on a full experiment's records with an exploring budget and a seed, seen after the
    exploring phases and at every refill budget, the larger budgets continuing where the smaller stopped."""
    exploration = RecordedExploration(runner, stitcher.catalog, stitcher.scenarios,
                                      settings.model_copy(update={"budget": explore, "seed": seed}))
    strategy = Strategy.RANDOM if plan == Plan.RANDOM else Strategy.PHASED
    if plan == Plan.RANDOM:
        random_allocation(exploration)
    else:
        phased_allocation(exploration)
    explored = len(exploration.assignments)
    refill_phase = candidate_phase if plan == Plan.CANDIDATE else counterpart_rounds
    spent = 0
    snapshots = []
    for refill in sorted(refills):
        spent += refill_phase(exploration, refill - spent, strategy, stitcher)
        snapshots.append(snapshot(exploration, strategy, refill, explored, spent, stitcher))
    return Trajectory(plan=plan, explore=explore, seed=seed, snapshots=tuple(snapshots))


def target_rank(snapshot: Snapshot, target: Callable[[str], bool]) -> int | None:
    """The best rank of a target chain among the stitched-only chains across layers, from 1."""
    return next((rank for rank, key in enumerate(snapshot.cross_layer, 1) if target(key)), None)


def budget_table(trajectories: list[Trajectory], target: Callable[[str], bool], full: Allocation) -> list[str]:
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
                     f"({injections / len(full.assignments):.0%} of {len(full.assignments)}), "
                     f"{fmean(one.unavailable for one in found):.0f} not recorded")
    return lines
