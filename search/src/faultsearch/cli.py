from pathlib import Path
from typing import Annotated, Final

import typer
from faultpoint.rules import Action
from faultpoint.tools.kinds import KindTable
from pydantic import BaseModel, TypeAdapter
from shop.deployment import SYSTEM as SHOP
from shop.deployment import System
from shop.upstream import PACKET_POINTS, UNSCOPED_TARGETS, UPSTREAM_SERVICES
from stitch_mechanism.deployment import SYSTEM as STITCH_MECHANISM

from faultsearch.allocation import (Allocation, AllocationSettings, Exploration, Strategy, extended_allocation,
                                    phased_allocation, random_allocation)
from faultsearch.catalog import (FROZEN, ActionTable, Catalog, Fault, build_catalog, control_executions, point_layer,
                                 point_manifests, point_scoped)
from faultsearch.chains import Stitching, stitch
from faultsearch.counterfactual import (EffectKey, NamedWorkload, Runner, RunSettings, Scenarios, tenant_names,
                                        treatment_record)
from faultsearch.edges import Condition, EdgeSet, EffectMap, build_edges, counterpart_assignments, holds
from faultsearch.report import render, summarise
from faultsearch.store import (ACTIONS_INPUT, ALLOCATION_SETTINGS, CATALOG, EFFECTS_INPUT, INPUTS, MAPPING_FEEDBACK,
                               REPORT, RUN_SETTINGS, SCENARIOS_INPUT, VALIDATIONS, Store, allocation_file,
                               chains_file, edges_file)
from faultsearch.validation import MappingFeedback, Validations, mapping_checks, merged_workload, selected, validate

app = typer.Typer(no_args_is_help=True, help=(
    "Causal stitching over faultpoint: inject faults into named workloads, stitch the causal edges across "
    "workloads into chains, and validate the chains end to end. Every record goes to runs/search/EXPERIMENT."))
Experiment = Annotated[str, typer.Argument(help="The experiment's name, its directory under runs/search.")]
Chosen = Annotated[Strategy, typer.Option(help="The allocation strategy.")]
SdkRoot = Annotated[Path, typer.Option(help="A clean checkout of the SDK commit the system runs with.")]
Rebuild = Annotated[bool, typer.Option(help="Build the SDK and the system first.")]
SYSTEMS: Final = {system.name: system for system in (SHOP, STITCH_MECHANISM)}
Explored = Annotated[str, typer.Option(help=f"The system to explore, one of {', '.join(SYSTEMS)}.")]


def services_by_port(system: System) -> dict[int, str]:
    return {port: service for service, port in system.ports.items()}


def recorded_system(store: Store) -> System:
    return SYSTEMS[store.load(RunSettings, RUN_SETTINGS).system]


def recorded_scenarios(store: Store, system: System) -> Scenarios:
    return store.record_input(Scenarios.read(system.scenarios), INPUTS, SCENARIOS_INPUT)


def recorded_runner(store: Store) -> Runner:
    settings = store.load(RunSettings, RUN_SETTINGS)
    system = SYSTEMS[settings.system]
    if system.verified_build(settings.sdk) != settings.commit:
        raise RuntimeError(f"the services are not built from {settings.commit}")
    return Runner(store, settings, system)


def scenario_catalog(store: Store, runner: Runner, scenarios: Scenarios) -> Catalog:
    """The catalog over the points of the manifests, of every scenario's controls and of the deployment's
    configuration."""
    controls = runner.controls([NamedWorkload(name=scenario.name, workload=scenarios.workload(scenario.name))
                                for scenario in scenarios.scenarios])
    executions = {control.workload.name: control_executions(
        [record for label in control.labels for record in runner.observations(label)], len(control.labels),
        len(tenant_names(control.workload.workload)), runner.kinds, UPSTREAM_SERVICES) for control in controls}
    actions = store.record_input(ActionTable.read(), INPUTS, ACTIONS_INPUT)
    return store.record_input(build_catalog(runner.system.manifests, executions, list(PACKET_POINTS), actions,
                                            runner.kinds, UPSTREAM_SERVICES), CATALOG)


def catalog_exploration(store: Store, runner: Runner, settings: AllocationSettings) -> Exploration:
    """An exploration over the catalog the controls of every recorded scenario give."""
    scenarios = recorded_scenarios(store, runner.system)
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
            rebuild: Rebuild = False, system: Explored = SHOP.name) -> None:
    """Run the controls of every scenario, build the fault catalog, and spend the budget with one strategy."""
    store = Store(experiment)
    sdk = sdk_root.resolve()
    explored = SYSTEMS[system]
    commit = explored.build(sdk) if rebuild else explored.verified_build(sdk)
    runner = Runner(store, store.record_input(RunSettings(
        sdk=sdk, commit=commit, repetitions=repetitions, alpha=alpha, min_mean_increase=min_mean_increase,
        workers=workers, pack_tenants=pack_tenants, system=system), RUN_SETTINGS), explored)
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
    system = recorded_system(recorded)
    commit = system.build(sdk) if rebuild else system.verified_build(sdk)
    runner = Runner(store, store.record_input(recorded.load(RunSettings, RUN_SETTINGS).model_copy(
        update={"sdk": sdk, "commit": commit}), RUN_SETTINGS), system)
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
    system = recorded_system(store)
    allocation = store.load(Allocation, allocation_file(strategy))
    records = [treatment_record(store, assignment.fault, assignment.scenario) for assignment in allocation.assignments]
    edges = build_edges(records, recorded_scenarios(store, system),
                        store.record_input(EffectMap.read(system.entry_service), INPUTS, EFFECTS_INPUT),
                        store.load(Catalog, CATALOG), KindTable.installed(), UPSTREAM_SERVICES, UNSCOPED_TARGETS,
                        services_by_port(system), point_manifests(system.manifests), min_count_increase)
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
    runner = recorded_runner(store)
    exploration = Exploration(runner, store.load(Catalog, CATALOG), recorded_scenarios(store, runner.system),
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
    runner = recorded_runner(store)
    validations = validate(runner,
                           selected(stitching, stitched_only, single_scenario, cross_layer, per_pair, chain, validated),
                           recorded_scenarios(store, runner.system), stitching.min_count_increase)
    store.save(validations, VALIDATIONS)
    feedback = store.load(MappingFeedback, MAPPING_FEEDBACK) if store.has(MAPPING_FEEDBACK) \
        else MappingFeedback(checks=())
    store.save(feedback.merged(mapping_checks(validations)), MAPPING_FEEDBACK)
    for validation in validations.validations:
        typer.echo(f"{'confirmed' if validation.confirmed else 'refuted'} {validation.selection} in "
                   f"{validation.workload.name}: {''.join('+' if hop.confirmed else '-' for hop in validation.hops)} "
                   f"{validation.chain.key}")


class Trial(BaseModel):
    """A fault to inject alone in the baseline workload with a condition's changes, as a validation injects a chain's
    first fault."""

    model_config = FROZEN

    point: str
    action: Action
    condition: Condition = {}


@app.command()
def trial(experiment: Experiment, sdk_root: SdkRoot,
          trials: Annotated[Path, typer.Option(help="A JSON list of trials: point, action and condition.")],
          system: Explored = SHOP.name, repetitions: int = 3, workers: int = 6, alpha: float = 0.1,
          min_mean_increase: float = 0.5,
          min_count_increase: Annotated[float, typer.Option(
              help="The smallest relative increase of a count that counts as an effect.")] = 0.2) -> None:
    """Inject given faults alone in given workloads, against controls of those workloads, and show every tenant's
    statuses and every effect: a check of what a constructed system does, before a search explores it."""
    store = Store(experiment)
    explored = SYSTEMS[system]
    runner = Runner(store, store.record_input(RunSettings(
        sdk=sdk_root.resolve(), commit=explored.verified_build(sdk_root.resolve()), repetitions=repetitions,
        alpha=alpha, min_mean_increase=min_mean_increase, workers=workers, pack_tenants=False, system=system),
        RUN_SETTINGS), explored)
    scenarios = recorded_scenarios(store, explored)
    pairs = [(Fault(point=item.point, action=item.action, layer=point_layer(item.point, UPSTREAM_SERVICES),
                    scoped=point_scoped(item.point, point_layer(item.point, UPSTREAM_SERVICES), runner.kinds)),
              merged_workload(item.condition, scenarios))
             for item in TypeAdapter(list[Trial]).validate_json(trials.read_bytes())]
    for (fault, workload), record in zip(pairs, runner.isolated_treatments(pairs), strict=True):
        typer.echo(f"== {fault.key} in {workload.name}: statuses {record.statuses[0]}, injected {record.injected}"
                   + (f", refused: {record.refusal}" if record.refusal else ""))
        for effect in record.effects:
            if holds(effect, min_count_increase):
                typer.echo(f"   {EffectKey.of(effect).key} {effect.verdict} {effect.control} -> {effect.treatment}")


@app.command()
def report(experiment: Experiment,
           edge: Annotated[list[str], typer.Option(help="An edge to look up, CAUSE-FAULT-KEY => EFFECT-KEY.")] = []) -> None:
    """Summarise the catalog, both strategies, the validations and the comparisons."""
    store = Store(experiment)
    summary = summarise(store, edge)
    store.save(summary, REPORT)
    typer.echo(render(summary))
