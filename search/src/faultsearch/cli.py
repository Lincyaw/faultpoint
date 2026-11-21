from pathlib import Path
from typing import Annotated, Final

import typer
from faultpoint.tools.kinds import KindTable
from shop.deployment import MANIFESTS, PORTS, build, verified_build
from shop.upstream import PACKET_POINTS, UNSCOPED_TARGETS, UPSTREAM_SERVICES
from shop.workload import Scenarios

from faultsearch.allocation import (Allocation, AllocationSettings, Exploration, Strategy, extended_allocation,
                                    phased_allocation, random_allocation)
from faultsearch.catalog import ActionTable, Catalog, build_catalog, control_executions, point_manifests
from faultsearch.chains import Stitching, stitch
from faultsearch.counterfactual import NamedWorkload, Runner, RunSettings, treatment_record
from faultsearch.edges import EdgeSet, EffectMap, build_edges, counterpart_assignments
from faultsearch.report import render, summarise
from faultsearch.store import (ACTIONS_INPUT, ALLOCATION_SETTINGS, CATALOG, EFFECTS_INPUT, INPUTS, MAPPING_FEEDBACK,
                               REPORT, RUN_SETTINGS, SCENARIOS_INPUT, VALIDATIONS, Store, allocation_file,
                               chains_file, edges_file)
from faultsearch.validation import MappingFeedback, Validations, mapping_checks, selected, validate

app = typer.Typer(no_args_is_help=True, help=(
    "Causal stitching over faultpoint: inject faults into named workloads, stitch the causal edges across "
    "workloads into chains, and validate the chains end to end. Every record goes to runs/search/EXPERIMENT."))
Experiment = Annotated[str, typer.Argument(help="The experiment's name, its directory under runs/search.")]
Chosen = Annotated[Strategy, typer.Option(help="The allocation strategy.")]
SdkRoot = Annotated[Path, typer.Option(help="A clean checkout of the SDK commit the shop runs with.")]
Rebuild = Annotated[bool, typer.Option(help="Build the SDK and the shop first.")]
SERVICES_BY_PORT: Final = {port: service for service, port in PORTS.items()}


def recorded_scenarios(store: Store) -> Scenarios:
    return store.record_input(Scenarios.read(), INPUTS, SCENARIOS_INPUT)


def recorded_runner(store: Store) -> Runner:
    settings = store.load(RunSettings, RUN_SETTINGS)
    if verified_build(settings.sdk) != settings.commit:
        raise RuntimeError(f"the services are not built from {settings.commit}")
    return Runner(store, settings)


def scenario_catalog(store: Store, runner: Runner, scenarios: Scenarios) -> Catalog:
    """The catalog over the points of the manifests, of every scenario's controls and of the deployment's
    configuration."""
    controls = runner.controls([NamedWorkload(name=scenario.name, workload=scenarios.workload(scenario.name))
                                for scenario in scenarios.scenarios])
    executions = {control.workload.name: control_executions(
        [record for label in control.labels for record in runner.observations(label)], len(control.labels),
        control.workload.workload.tenants, runner.kinds, UPSTREAM_SERVICES) for control in controls}
    actions = store.record_input(ActionTable.read(), INPUTS, ACTIONS_INPUT)
    return store.record_input(build_catalog(MANIFESTS, executions, list(PACKET_POINTS), actions, runner.kinds,
                                            UPSTREAM_SERVICES), CATALOG)


def catalog_exploration(store: Store, runner: Runner, settings: AllocationSettings) -> Exploration:
    """An exploration over the catalog the controls of every recorded scenario give."""
    scenarios = recorded_scenarios(store)
    catalog = scenario_catalog(store, runner, scenarios)
    typer.echo(f"catalog: {len(catalog.faults)} faults, {len(catalog.excluded)} points excluded")
    return Exploration(runner, catalog, scenarios, store.record_input(settings, ALLOCATION_SETTINGS))


@app.command()
def explore(experiment: Experiment, sdk_root: SdkRoot, strategy: Chosen = Strategy.PHASED,
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
            pack_tenants: Annotated[bool, typer.Option(
                help="Let faults share repetitions in different tenants; off when upstream components are "
                     "observed.")] = True,
            rebuild: Rebuild = False) -> None:
    """Run the controls of every scenario, build the fault catalog, and spend the budget with one strategy."""
    store = Store(experiment)
    sdk = sdk_root.resolve()
    commit = build(sdk) if rebuild else verified_build(sdk)
    runner = Runner(store, store.record_input(RunSettings(
        sdk=sdk, commit=commit, repetitions=repetitions, alpha=alpha, min_mean_increase=min_mean_increase,
        workers=workers, pack_tenants=pack_tenants), RUN_SETTINGS))
    exploration = catalog_exploration(store, runner, AllocationSettings(
        budget=budget, seed=seed, round_robin_share=round_robin_share, cluster_distance=cluster_distance,
        epsilon=epsilon, batch=batch))
    allocation = phased_allocation(exploration) if strategy == Strategy.PHASED else random_allocation(exploration)
    store.save(allocation, allocation_file(strategy))
    typer.echo(f"{strategy}: {len(allocation.assignments)} injections, {len(allocation.clusters)} clusters")


@app.command()
def replay(experiment: Experiment,
           source: Annotated[str, typer.Option(help="The experiment whose phased assignments to run again.")],
           sdk_root: SdkRoot, rebuild: Rebuild = False) -> None:
    """Run another experiment's phased assignments again with another SDK build, under that experiment's scenarios
    and settings, then every fault of the catalog they leave out once, such as those of a new fault source."""
    store = Store(experiment)
    recorded = Store(source)
    sdk = sdk_root.resolve()
    commit = build(sdk) if rebuild else verified_build(sdk)
    runner = Runner(store, store.record_input(recorded.load(RunSettings, RUN_SETTINGS).model_copy(
        update={"sdk": sdk, "commit": commit}), RUN_SETTINGS))
    store.record_input(recorded.load(Scenarios, INPUTS, SCENARIOS_INPUT), INPUTS, SCENARIOS_INPUT)
    exploration = catalog_exploration(store, runner, recorded.load(AllocationSettings, ALLOCATION_SETTINGS))
    assignments = recorded.load(Allocation, allocation_file(Strategy.PHASED)).assignments
    allocation = extended_allocation(exploration, Strategy.PHASED, [
        assignment.model_copy(update={"fault": exploration.catalog.by_key[assignment.fault.key]})
        for assignment in assignments])
    store.save(allocation, allocation_file(Strategy.PHASED))
    typer.echo(f"replayed {len(assignments)} assignments of {source}: {len(allocation.assignments)} injections, "
               f"{len(allocation.clusters)} clusters")


@app.command("stitch")
def stitch_command(experiment: Experiment, strategy: Chosen = Strategy.PHASED,
                   width: Annotated[int, typer.Option(help="Partial chains kept at every length.")] = 20000,
                   max_hops: int = 4,
                   kept: Annotated[int, typer.Option(help="Ranked chains written in full.")] = 300,
                   min_count_increase: Annotated[float, typer.Option(
                       help="The smallest relative increase of a count that counts as an effect.")] = 0.2) -> None:
    """Learn the edges of a strategy's injections and stitch them into ranked chains and cycles, leaving out the
    steps from an effect through a counterpart to a consequence that validations refuted."""
    store = Store(experiment)
    allocation = store.load(Allocation, allocation_file(strategy))
    records = [treatment_record(store, assignment.fault, assignment.scenario) for assignment in allocation.assignments]
    edges = build_edges(records, recorded_scenarios(store),
                        store.record_input(EffectMap.read(), INPUTS, EFFECTS_INPUT), store.load(Catalog, CATALOG),
                        KindTable.installed(), UPSTREAM_SERVICES, UNSCOPED_TARGETS, SERVICES_BY_PORT,
                        point_manifests(MANIFESTS), min_count_increase)
    store.save(EdgeSet(strategy=strategy, edges=tuple(edges)), edges_file(strategy))
    refuted = store.load(MappingFeedback, MAPPING_FEEDBACK).refuted() if store.has(MAPPING_FEEDBACK) else frozenset()
    stitching = stitch(edges, allocation, records, width, max_hops, kept, min_count_increase, refuted)
    store.save(stitching, chains_file(strategy))
    needed = counterpart_assignments(edges, {assignment.fault.key for assignment in allocation.assignments})
    typer.echo(f"{strategy}: {len(edges)} edges, {stitching.chains} chains ({stitching.stitched_only} stitched only, "
               f"{stitching.single_scenario} shown end to end by one scenario), {len(stitching.cycles)} cycles; "
               f"{len(needed)} counterpart injections not yet run")


@app.command()
def complete(experiment: Experiment) -> None:
    """Inject, each where its effect appeared, the faults that correspond to the effects of the last stitching's edges
    and that no assignment of the phased allocation tried, so that the next stitching continues through them."""
    store = Store(experiment)
    allocation = store.load(Allocation, allocation_file(Strategy.PHASED))
    needed = counterpart_assignments(list(store.load(EdgeSet, edges_file(Strategy.PHASED)).edges),
                                     {assignment.fault.key for assignment in allocation.assignments})
    exploration = Exploration(recorded_runner(store), store.load(Catalog, CATALOG), recorded_scenarios(store),
                              store.load(AllocationSettings, ALLOCATION_SETTINGS))
    completed = extended_allocation(exploration, Strategy.PHASED, [*allocation.assignments, *needed])
    store.save(completed, allocation_file(Strategy.PHASED))
    typer.echo(f"{len(needed)} counterpart injections: {len(completed.assignments)} injections, "
               f"{len(completed.clusters)} clusters")


@app.command("validate")
def validate_command(experiment: Experiment,
                     stitched_only: Annotated[int, typer.Option(help="Best chains that exist only by stitching.")] = 10,
                     single_scenario: Annotated[int, typer.Option(help="Best chains one scenario showed.")] = 3,
                     cross_layer: Annotated[int, typer.Option(
                         help="Best stitched-only chains across layers, besides those chosen already.")] = 0,
                     per_pair: Annotated[int, typer.Option(
                         help="Most of those chains with the same layer of the first fault and the same last "
                              "effect.")] = 3,
                     chain: Annotated[list[str], typer.Option(help="A chain to validate besides, by its key.")] = []
                     ) -> None:
    """Inject only the first fault of the best chains of the phased allocation in the workload their conditions
    merge into, and keep what each validated hop says about the effect map's correspondences."""
    store = Store(experiment)
    stitching = store.load(Stitching, chains_file(Strategy.PHASED))
    validated = [validation.chain for validation in store.load(Validations, VALIDATIONS).validations] \
        if store.has(VALIDATIONS) else []
    validations = validate(recorded_runner(store),
                           selected(stitching, stitched_only, single_scenario, cross_layer, per_pair, chain, validated),
                           recorded_scenarios(store), stitching.min_count_increase)
    store.save(validations, VALIDATIONS)
    feedback = store.load(MappingFeedback, MAPPING_FEEDBACK) if store.has(MAPPING_FEEDBACK) \
        else MappingFeedback(checks=())
    store.save(feedback.merged(mapping_checks(validations)), MAPPING_FEEDBACK)
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
