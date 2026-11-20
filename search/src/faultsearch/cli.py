from pathlib import Path
from typing import Annotated

import typer
from shop.deployment import MANIFESTS, build, verified_build
from shop.workload import Scenarios

from faultsearch.allocation import (Allocation, AllocationSettings, Exploration, Strategy, phased_allocation,
                                    random_allocation)
from faultsearch.catalog import ActionTable, Catalog, build_catalog, tenant_executions
from faultsearch.chains import Stitching, stitch
from faultsearch.counterfactual import NamedWorkload, Runner, RunSettings, treatment_record
from faultsearch.edges import EdgeSet, EffectMap, build_edges
from faultsearch.report import render, summarise
from faultsearch.store import (ACTIONS_INPUT, ALLOCATION_SETTINGS, CATALOG, EFFECTS_INPUT, INPUTS, REPORT,
                               RUN_SETTINGS, SCENARIOS_INPUT, VALIDATIONS, Store, allocation_file, chains_file,
                               edges_file)
from faultsearch.validation import selected, validate

app = typer.Typer(no_args_is_help=True, help=(
    "Causal stitching over faultpoint: inject faults into named workloads, stitch the causal edges across "
    "workloads into chains, and validate the chains end to end. Every record goes to runs/search/EXPERIMENT."))
Experiment = Annotated[str, typer.Argument(help="The experiment's name, its directory under runs/search.")]
Chosen = Annotated[Strategy, typer.Option(help="The allocation strategy.")]


def recorded_scenarios(store: Store) -> Scenarios:
    return store.record_input(Scenarios.read(), INPUTS, SCENARIOS_INPUT)


def recorded_runner(store: Store) -> Runner:
    settings = store.load(RunSettings, RUN_SETTINGS)
    if verified_build(settings.sdk) != settings.commit:
        raise RuntimeError(f"the services are not built from {settings.commit}")
    return Runner(store, settings)


def scenario_catalog(store: Store, runner: Runner, scenarios: Scenarios) -> Catalog:
    """The catalog over the points of the manifests and of every scenario's controls."""
    controls = runner.controls([NamedWorkload(name=scenario.name, workload=scenarios.workload(scenario.name))
                                for scenario in scenarios.scenarios])
    executions = {control.workload.name: tenant_executions(
        [record for label in control.labels for record in runner.observations(label)], len(control.labels),
        control.workload.workload.tenants) for control in controls}
    actions = store.record_input(ActionTable.read(), INPUTS, ACTIONS_INPUT)
    return store.record_input(build_catalog(MANIFESTS, executions, actions), CATALOG)


@app.command()
def explore(experiment: Experiment,
            sdk_root: Annotated[Path, typer.Option(help="A clean checkout of the SDK commit the shop runs with.")],
            strategy: Chosen = Strategy.PHASED,
            budget: Annotated[int, typer.Option(help="Injections, (fault, scenario) pairs, per strategy.")] = 200,
            seed: int = 1,
            repetitions: Annotated[int, typer.Option(help="Control and treatment repetitions each.")] = 3,
            alpha: float = 0.1,
            min_mean_increase: Annotated[float, typer.Option(help="The smallest relative increase of a mean.")] = 0.5,
            workers: Annotated[int, typer.Option(help="Repetitions run side by side.")] = 6,
            round_robin_share: float = 0.5,
            cluster_distance: float = 0.5,
            epsilon: float = 0.05,
            batch: int = 18,
            rebuild: Annotated[bool, typer.Option(help="Build the SDK and the shop first.")] = False) -> None:
    """Run the controls of every scenario, build the fault catalog, and spend the budget with one strategy."""
    store = Store(experiment)
    sdk = sdk_root.resolve()
    commit = build(sdk) if rebuild else verified_build(sdk)
    runner = Runner(store, store.record_input(RunSettings(
        sdk=sdk, commit=commit, repetitions=repetitions, alpha=alpha, min_mean_increase=min_mean_increase,
        workers=workers), RUN_SETTINGS))
    settings = store.record_input(AllocationSettings(
        budget=budget, seed=seed, round_robin_share=round_robin_share, cluster_distance=cluster_distance,
        epsilon=epsilon, batch=batch), ALLOCATION_SETTINGS)
    scenarios = recorded_scenarios(store)
    catalog = scenario_catalog(store, runner, scenarios)
    typer.echo(f"catalog: {len(catalog.faults)} faults, {len(catalog.excluded)} points excluded")
    exploration = Exploration(runner, catalog, scenarios, settings)
    allocation = phased_allocation(exploration) if strategy == Strategy.PHASED else random_allocation(exploration)
    store.save(allocation, allocation_file(strategy))
    typer.echo(f"{strategy}: {len(allocation.assignments)} injections, {len(allocation.clusters)} clusters")


@app.command("stitch")
def stitch_command(experiment: Experiment, strategy: Chosen = Strategy.PHASED,
                   width: Annotated[int, typer.Option(help="Partial chains kept at every length.")] = 20000,
                   max_hops: int = 4,
                   kept: Annotated[int, typer.Option(help="Ranked chains written in full.")] = 300) -> None:
    """Learn the edges of a strategy's injections and stitch them into ranked chains and cycles."""
    store = Store(experiment)
    allocation = store.load(Allocation, allocation_file(strategy))
    records = [treatment_record(store, assignment.fault, assignment.scenario) for assignment in allocation.assignments]
    edges = build_edges(records, recorded_scenarios(store),
                        store.record_input(EffectMap.read(), INPUTS, EFFECTS_INPUT), store.load(Catalog, CATALOG))
    store.save(EdgeSet(strategy=strategy, edges=tuple(edges)), edges_file(strategy))
    stitching = stitch(edges, allocation, records, width, max_hops, kept)
    store.save(stitching, chains_file(strategy))
    typer.echo(f"{strategy}: {len(edges)} edges, {stitching.chains} chains ({stitching.stitched_only} stitched only, "
               f"{stitching.single_scenario} shown end to end by one scenario), {len(stitching.cycles)} cycles")


@app.command("validate")
def validate_command(experiment: Experiment,
                     stitched_only: Annotated[int, typer.Option(help="Best chains that exist only by stitching.")] = 10,
                     single_scenario: Annotated[int, typer.Option(help="Best chains one scenario showed.")] = 3,
                     chain: Annotated[list[str], typer.Option(help="A chain to validate besides, by its key.")] = []
                     ) -> None:
    """Inject only the first fault of the best chains of the phased allocation in the workload their conditions
    merge into."""
    store = Store(experiment)
    stitching = store.load(Stitching, chains_file(Strategy.PHASED))
    validations = validate(recorded_runner(store), selected(stitching, stitched_only, single_scenario, chain),
                           recorded_scenarios(store))
    store.save(validations, VALIDATIONS)
    for validation in validations.validations:
        typer.echo(f"{'confirmed' if validation.confirmed else 'refuted'} {validation.selection} in "
                   f"{validation.workload.name}: {''.join('+' if hop.confirmed else '-' for hop in validation.hops)} "
                   f"{validation.chain.key}")


@app.command()
def report(experiment: Experiment,
           edge: Annotated[list[str], typer.Option(help="An edge to look up, CAUSE-FAULT-KEY => EFFECT-KEY.")] = []) -> None:
    """Summarise the catalog, both strategies, the validations and the comparisons."""
    store = Store(experiment)
    summary = summarise(store, edge)
    store.save(summary, REPORT)
    typer.echo(render(summary))
