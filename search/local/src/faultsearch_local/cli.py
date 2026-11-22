import math
from collections import Counter
from pathlib import Path
from typing import Annotated, Final

import typer
from faultpoint.rules import Action
from faultpoint.tools.kinds import KindTable
from faultsearch.allocation import AllocationSettings, Strategy
from faultsearch.catalog import FROZEN, Fault, point_layer, point_scoped
from faultsearch.counterfactual import EffectKey, Group, Scenarios
from faultsearch.edges import Condition, EffectMap, holds
from faultsearch.execution import RunRequest
from faultsearch.facts import FACTS_FILE, LoadVariants, Purpose, SystemTopology, read_facts, write_facts
from faultsearch.graph import ComputeSettings, FactGraph, FactRepetitions, compute_graph
from faultsearch.plan import PlanSettings, PlanState, Refill, ValidationSettings, search
from faultsearch.recording import point_inventory
from faultsearch.validation import merged_workload
from pydantic import BaseModel, JsonValue, TypeAdapter

from faultsearch_local.budget import BUDGETS, Comparison, Plan, Trajectory, budget_table
from faultsearch_local.executor import LocalExecutor, RunSettings
from faultsearch_local.report import render, summarise
from faultsearch_local.run_directories import experiment_facts, graph_differences
from faultsearch_local.store import (ALLOCATION_SETTINGS, INPUTS, REPORT, RUN_SETTINGS, SCENARIOS_INPUT, FactLog,
                                     Store)
from faultsearch_local.systems import System, installed_systems

app = typer.Typer(no_args_is_help=True, help=(
    "Causal stitching over faultpoint: plan and run injections into named workloads as search runs appended to "
    "runs/search/EXPERIMENT/facts.jsonl, and compute from those facts the causal edges, the chains stitched across "
    "workloads and their judgement end to end."))
Experiment = Annotated[str, typer.Argument(help="The experiment's name, its directory under runs/search.")]
SdkRoot = Annotated[Path, typer.Option(help="A clean checkout of the SDK commit the system runs with.")]
SYSTEMS: Final = installed_systems()
SHOP: Final = "shop"
Explored = Annotated[str, typer.Option(help=f"The system to explore, one of {', '.join(SYSTEMS)}.")]
MaxLoad = Annotated[float, typer.Option(
    help="The host's 1-minute load above which no new repetition starts while others still run.")]
KEPT: Final = 2000
"""The ranked chains a graph keeps in full, those the validation chooses from."""
PLAN_SETTINGS: Final = "plan-settings.json"
PLAN_STATE: Final = "plan-state.json"


def recorded_system(store: Store) -> System:
    return SYSTEMS[store.load(RunSettings, RUN_SETTINGS).system]


def recorded_scenarios(store: Store, system: System) -> Scenarios:
    return store.record_input(Scenarios.read(system.scenarios), INPUTS, SCENARIOS_INPUT)


def recorded_settings(store: Store) -> ComputeSettings:
    """The graph settings of an experiment's comparison thresholds and clustering."""
    settings = store.load(RunSettings, RUN_SETTINGS)
    clustering = {"cluster_distance": store.load(AllocationSettings, ALLOCATION_SETTINGS).cluster_distance} \
        if store.has(ALLOCATION_SETTINGS) else {}
    return ComputeSettings(alpha=settings.alpha, kept=KEPT, min_mean_increase=settings.min_mean_increase, **clustering)


def started_log(store: Store, system: System) -> FactLog:
    """The experiment's fact log, begun with the system's topology and load variants when it is new."""
    log = FactLog(store.path(FACTS_FILE))
    if not log.facts:
        log.append(SystemTopology(sequence=1, system=system.name, upstream=system.upstream,
                                  entry_service=system.entry_service,
                                  terminal_outcomes=EffectMap.read(system.entry_service).terminal_outcomes,
                                  ports=system.ports, targets=system.targets))
        log.append(LoadVariants(sequence=2, system=system.name, scenarios=recorded_scenarios(store, system)))
    return log


@app.command("search")
def search_command(
        experiment: Experiment, sdk_root: SdkRoot, system: Explored = SHOP,
        strategy: Annotated[Strategy, typer.Option(help="How the exploring budget is spent.")] = Strategy.PHASED,
        budget: Annotated[int, typer.Option(help="Exploring injections, (fault, scenario) pairs.")] = 200,
        seed: int = 1,
        repetitions: Annotated[int, typer.Option(help="Control and treatment repetitions each.")] = 3,
        alpha: float = 0.1,
        min_mean_increase: Annotated[float, typer.Option(help="The smallest relative increase of a mean.")] = 0.5,
        workers: Annotated[int, typer.Option(help="Repetitions run side by side.")] = 6,
        round_robin_share: float = 0.5, cluster_distance: float = 0.5, epsilon: float = 0.05, batch: int = 18,
        pack_tenants: Annotated[bool, typer.Option(
            help="Let faults share repetitions in different tenants; off when upstream components are "
                 "observed.")] = True,
        refill: Annotated[Refill, typer.Option(help="How the refill budget is spent on counterparts.")] = Refill.ROUNDS,
        refill_budget: Annotated[int, typer.Option(help="Counterpart injections the refill may spend.")] = 0,
        validation_runs: Annotated[int, typer.Option(help="Path runs the ranked chains choose.")] = 10,
        validation_batch: Annotated[int, typer.Option(
            help="Path runs chosen at once, before their checks update the chances that rank the candidates.")] = 5,
        per_group: Annotated[int, typer.Option(help="Most path runs one group of chains chooses.")] = 3,
        single_scenario_cross_layer: Annotated[int, typer.Option(
            help="Best chains across layers one scenario showed, judged as controls.")] = 3,
        chain: Annotated[list[str], typer.Option(help="A chain to judge besides, by its key.")] = [],
        instrumentation: Annotated[Path | None, typer.Option(
            help="The system's instrumentation JSON; omitted uses the registered system's configuration.")] = None,
        rebuild: Annotated[bool, typer.Option(help="Build the SDK and the system first.")] = False,
        max_load: MaxLoad = math.inf) -> None:
    """Plan and run a search until its plan ends: the controls of every scenario, the exploring stages, the refill,
    the merged workloads' controls and the validation batches, every request's search runs appended to the
    experiment's facts. The settings are recorded the first time; a search resumes from its saved plan state."""
    store = Store(experiment)
    sdk = sdk_root.resolve()
    explored = SYSTEMS[system]
    commit = explored.build(sdk) if rebuild else explored.verified_build(sdk)
    run_settings = store.record_input(RunSettings(
        sdk=sdk, commit=commit, repetitions=repetitions, alpha=alpha, min_mean_increase=min_mean_increase,
        workers=workers, pack_tenants=pack_tenants, system=system,
        instrumentation=explored.instrumentation if instrumentation is None
        else TypeAdapter(dict[str, JsonValue]).validate_json(instrumentation.read_bytes())),
        RUN_SETTINGS)
    allocation = store.record_input(AllocationSettings(budget=budget, seed=seed, round_robin_share=round_robin_share,
                                                       cluster_distance=cluster_distance, epsilon=epsilon, batch=batch),
                                    ALLOCATION_SETTINGS)
    settings = store.record_input(PlanSettings(
        strategy=strategy, allocation=allocation, repetitions=repetitions, pack_tenants=pack_tenants, refill=refill,
        refill_budget=refill_budget,
        validation=ValidationSettings(runs=validation_runs, batch=validation_batch, per_group=per_group,
                                      single_scenario_cross_layer=single_scenario_cross_layer, chains=tuple(chain)),
        compute=recorded_settings(store)), PLAN_SETTINGS)
    log = started_log(store, explored)

    def saved(state: PlanState) -> None:
        store.save(state, PLAN_STATE)
        typer.echo(f"plan: {state.stage}, {state.spent} explored, {state.refilled} refilled, "
                   f"{state.validated} validated", err=True)

    state = search(log, store.load(PlanState, PLAN_STATE) if store.has(PLAN_STATE) else PlanState.start(settings),
                   settings, LocalExecutor(store, run_settings, explored, log, max_load),
                   lambda labels, sequence: point_inventory(log.snapshot(), labels, explored.manifests,
                                                            explored.configured, sequence),
                   saved)
    typer.echo(f"search done: {state.spent} exploring and {state.refilled} refill injections asked for, "
               f"{len(log.facts)} facts")


def experiment_graph(store: Store) -> FactGraph:
    return FactGraph(read_facts(store.path(FACTS_FILE)), recorded_settings(store))


@app.command("chains")
def chains_command(experiment: Experiment,
                   first: Annotated[str, typer.Option(help="The start of the first fault's key.")] = "",
                   last: Annotated[str, typer.Option(help="The end of the last effect's key.")] = "",
                   through: Annotated[list[str], typer.Option(help="Text the chain's key contains.")] = [],
                   shown: Annotated[int, typer.Option(help="The most chains shown.")] = 20) -> None:
    """The ranked chains of an experiment's graph, stitched without any judgement, from a first fault to a last
    effect, with their rank among all chains and, for a stitched-only chain across layers ending in a failure the
    user sees, among those; ranks are exact within the chains the graph keeps in full."""
    stitching = experiment_graph(Store(experiment)).stitching
    kept = {chain.key: chain for chain in (*stitching.top, *stitching.top_cross_layer)}
    across = [key for key in stitching.keys
              if key in kept and kept[key].stitched_only and kept[key].crosses_layers and kept[key].terminal]
    found = [(rank, key) for rank, key in enumerate(stitching.keys, 1)
             if key.startswith(f"[{first}") and key.endswith(last) and all(text in key for text in through)]
    typer.echo(f"{len(found)} of {len(stitching.keys)} chains match; {len(stitching.top)} kept in full by rank")
    for rank, key in found[:shown]:
        chain = kept.get(key)
        places = ["not kept"] if chain is None else [
            str(chain.visibility), *([f"cross-layer {across.index(key) + 1}"] if key in across else [])]
        typer.echo(f"#{rank} ({', '.join(places)}) condition {chain.condition if chain else '-'}: {key}")


class Trial(BaseModel):
    """A fault to inject alone in the baseline workload with a condition's changes, as a validation injects a chain's
    first fault."""

    model_config = FROZEN

    point: str
    action: Action
    probability: float = 1.0
    condition: Condition = {}


@app.command()
def trial(experiment: Experiment, sdk_root: SdkRoot,
          trials: Annotated[Path, typer.Option(help="A JSON list of trials: point, action and condition.")],
          system: Explored = SHOP, repetitions: int = 3, workers: int = 6, alpha: float = 0.1,
          min_mean_increase: float = 0.5,
          min_count_increase: Annotated[float, typer.Option(
              help="The smallest relative increase of a count that counts as an effect.")] = 0.2,
          max_load: MaxLoad = math.inf) -> None:
    """Inject given faults alone in given workloads, against controls of those workloads, and show every tenant's
    statuses and every effect: a check of what a constructed system does, before a search explores it."""
    store = Store(experiment)
    explored = SYSTEMS[system]
    settings = store.record_input(RunSettings(
        sdk=sdk_root.resolve(), commit=explored.verified_build(sdk_root.resolve()), repetitions=repetitions,
        alpha=alpha, min_mean_increase=min_mean_increase, workers=workers, pack_tenants=False, system=system,
        instrumentation=explored.instrumentation), RUN_SETTINGS)
    log = FactLog(store.path(FACTS_FILE))
    scenarios = recorded_scenarios(store, explored)
    kinds = KindTable.installed()
    requests = [RunRequest(workload=merged_workload(item.condition, scenarios), faults=(Fault(
        point=item.point, action=item.action, layer=point_layer(item.point, explored.upstream),
        scoped=point_scoped(item.point, point_layer(item.point, explored.upstream), kinds),
        probability=item.probability),), purpose=Purpose.PATH, repetitions=repetitions)
        for item in TypeAdapter(list[Trial]).validate_json(trials.read_bytes())]
    controls = [RunRequest(workload=workload, purpose=Purpose.PATH, repetitions=repetitions)
                for workload in {request.workload.name: request.workload for request in requests}.values()]
    LocalExecutor(store, settings, explored, log, max_load).run(controls + requests)
    read = FactRepetitions(log.snapshot().standing_runs(),
                           ComputeSettings(alpha=alpha, min_mean_increase=min_mean_increase))
    labels = {control.workload.name: tuple(control.labels()) for control in controls}
    for request in requests:
        record = read.group_records(Group(workload=request.workload, faults=request.faults),
                                    labels[request.workload.name], request.labels())[0]
        typer.echo(f"== {record.fault.key} in {request.workload.name}: statuses {record.statuses[0]}, injected "
                   f"{record.injected}, seeds {record.seeds}" + (f", refused: {record.refusal}" if record.refusal else ""))
        for effect in record.effects:
            if holds(effect, min_count_increase):
                typer.echo(f"   {EffectKey.of(effect).key} {effect.verdict} {effect.control} -> {effect.treatment}")


@app.command()
def report(experiment: Experiment,
           edge: Annotated[list[str], typer.Option(help="An edge to look up, CAUSE-FAULT-KEY => EFFECT-KEY.")] = []) -> None:
    """Summarise an experiment's graph: the catalog, the allocation, the edges and chains, and the judgement."""
    store = Store(experiment)
    summary = summarise(store, experiment_graph(store), edge)
    store.save(summary, REPORT)
    typer.echo(render(summary))


@app.command()
def budgets(experiment: Experiment,
            explore: Annotated[list[int], typer.Option(help="An exploring budget, in (fault, scenario) pairs.")],
            refill: Annotated[list[int], typer.Option(help="A refill budget, in counterpart injections.")],
            seed: Annotated[list[int], typer.Option(help="A seed every plan runs with.")],
            plan: Annotated[list[Plan], typer.Option(help="A plan to compare.")] = list(Plan),
            first: Annotated[str, typer.Option(help="The start of a target chain's first fault's key.")] = "",
            last: Annotated[str, typer.Option(help="The end of a target chain's last effect's key.")] = "",
            through: Annotated[list[str], typer.Option(help="Text a target chain's key contains.")] = [],
            hops: Annotated[int, typer.Option(help="A target chain's hops, any number when 0.")] = 0) -> None:
    """Compare plans offline on a full experiment's facts, running nothing: every plan, exploring budget and seed
    spends the refill budgets in turn, each larger budget continuing with a new round, and is judged from the full
    experiment's path runs alone; a request the facts lack is counted. Trajectories already compared are read back;
    the table shows a target chain's ranks among the stitched-only chains across layers ending at the user."""
    store = Store(experiment)
    run_settings = store.load(RunSettings, RUN_SETTINGS)
    comparison = Comparison(read_facts(store.path(FACTS_FILE)), recorded_settings(store),
                            store.load(AllocationSettings, ALLOCATION_SETTINGS), run_settings.repetitions,
                            run_settings.pack_tenants)
    trajectories = []
    for chosen_plan in plan:
        for budget in explore:
            for chosen_seed in seed:
                name = f"{chosen_plan}-explore{budget}-seed{chosen_seed}.json"
                if not store.has(BUDGETS, name):
                    store.save(comparison.simulate(chosen_plan, budget, refill, chosen_seed), BUDGETS, name)
                    typer.echo(f"compared {name}")
                trajectory = store.load(Trajectory, BUDGETS, name)
                if [found.refill for found in trajectory.snapshots] != sorted(refill):
                    raise ValueError(f"{name} was compared at other refill budgets")
                trajectories.append(trajectory)
    for line in budget_table(trajectories, lambda key: key.startswith(f"[{first}") and key.endswith(last)
                             and all(text in key for text in through) and hops in (0, key.count(" -> ") + 1),
                             comparison.full):
        typer.echo(line)


@app.command("import-facts")
def import_facts(experiment: Experiment) -> None:
    """Convert an experiment directory written before facts into facts, written to its facts.jsonl: the system's
    topology and load variants, the point inventory, and a search run for every repetition a control, treatment or
    validation record of the experiment refers to. The other repetition directories are left out and counted."""
    store = Store(experiment)
    imported = experiment_facts(store, recorded_system(store))
    write_facts(store.path(FACTS_FILE), imported.facts)
    kinds = Counter(str(fact.kind) for fact in imported.facts.facts)
    purposes = Counter(str(fact.purpose) for fact in imported.facts.standing_runs())
    typer.echo(f"{len(imported.facts.facts)} facts: {dict(kinds)}; search runs by purpose {dict(purposes)}")
    typer.echo(f"left out: {len(imported.unreferenced)} repetitions that ran to their end but no record of the "
               f"experiment refers to, by workload {dict(Counter(label.split('.')[0] for label in imported.unreferenced))};"
               f" {len(imported.unfinished)} that never ran to their end")


@app.command("graph-check")
def graph_check(experiment: Experiment,
                kept: Annotated[int, typer.Option(help="Ranked chains the experiment's stitching wrote in full.")]
                = KEPT) -> None:
    """Compute the propagation graph from the facts.jsonl of an experiment directory written before facts and
    compare it, part by part, with the records that experiment's own commands wrote."""
    store = Store(experiment)
    graph = compute_graph(read_facts(store.path(FACTS_FILE)),
                          recorded_settings(store).model_copy(update={"kept": kept}))
    for line in graph_differences(graph, store):
        typer.echo(line)
