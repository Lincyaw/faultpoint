from collections import Counter
from pathlib import Path
from typing import Annotated, Final

import typer
from faultpoint.rules import Action
from faultpoint.tools.kinds import KindTable
from pydantic import BaseModel, TypeAdapter
from shop.deployment import SYSTEM as SHOP
from shop.deployment import System
from shop.upstream import PACKET_POINTS, UNSCOPED_TARGETS, UPSTREAM_SERVICES
from stitch_mechanism.deployment import SYSTEMS as STITCH_MECHANISM_BUILDS

from faultsearch.allocation import (Allocation, AllocationSettings, Exploration, Strategy, extended_allocation,
                                    phased_allocation, random_allocation)
from faultsearch.catalog import (FROZEN, ActionTable, Catalog, Fault, build_catalog, control_executions, point_layer,
                                 point_manifests, point_scoped)
from faultsearch.chains import Stitching, stitch
from faultsearch.counterfactual import (EffectKey, NamedWorkload, Runner, RunSettings, Scenarios, tenant_names,
                                        treatment_record)
from faultsearch.edges import Condition, EdgeSet, EffectMap, build_edges, counterpart_assignments, holds
from faultsearch.report import render, summarise
from faultsearch.store import (ACTIONS_INPUT, ALLOCATION_SETTINGS, CATALOG, EFFECTS_INPUT, HEADROOM, INPUTS,
                               MAPPING_FEEDBACK, REPORT, RUN_SETTINGS, SCENARIOS_INPUT, VALIDATIONS, Store,
                               allocation_file, chains_file, edges_file)
from faultsearch.evidence import MappingFeedback
from faultsearch.validation import (Headroom, Selection, Validations, adjudications, chosen_runs, headroom,
                                    mapping_checks, merged_workload, validate)

app = typer.Typer(no_args_is_help=True, help=(
    "Causal stitching over faultpoint: inject faults into named workloads, stitch the causal edges across "
    "workloads into chains, and validate the chains end to end. Every record goes to runs/search/EXPERIMENT."))
Experiment = Annotated[str, typer.Argument(help="The experiment's name, its directory under runs/search.")]
Chosen = Annotated[Strategy, typer.Option(help="The allocation strategy.")]
SdkRoot = Annotated[Path, typer.Option(help="A clean checkout of the SDK commit the system runs with.")]
Rebuild = Annotated[bool, typer.Option(help="Build the SDK and the system first.")]
SYSTEMS: Final = {system.name: system for system in (SHOP, *STITCH_MECHANISM_BUILDS)}
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
    feedback = store.load(MappingFeedback, MAPPING_FEEDBACK) if store.has(MAPPING_FEEDBACK) \
        else MappingFeedback(checks=())
    stitching = stitch(edges, allocation, records, width, max_hops, kept, min_count_increase, feedback)
    store.save(stitching, chains_file(strategy))
    needed = counterpart_assignments(edges, {assignment.fault.key for assignment in allocation.assignments})
    typer.echo(f"{strategy}: {len(edges)} edges, {stitching.chains} chains ({stitching.stitched_only} stitched only, "
               f"{stitching.single_scenario} shown end to end by one scenario, {stitching.undetermined} undetermined), "
               f"{len(stitching.cycles)} cycles; {len(needed)} counterpart injections not yet run")


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


@app.command("chains")
def chains_command(experiment: Experiment,
                   first: Annotated[str, typer.Option(help="The start of the first fault's key.")] = "",
                   last: Annotated[str, typer.Option(help="The end of the last effect's key.")] = "",
                   through: Annotated[list[str], typer.Option(help="Text the chain's key contains.")] = [],
                   shown: Annotated[int, typer.Option(help="The most chains shown.")] = 20) -> None:
    """The ranked chains of the phased stitching from a first fault to a last effect, with their rank among all
    chains and, for a stitched-only chain across layers ending in a failure the user sees, among those and among
    those whose count hops have headroom, once a validation measured it; ranks are exact within the chains the
    stitching kept in full."""
    store = Store(experiment)
    stitching = store.load(Stitching, chains_file(Strategy.PHASED))
    kept = {chain.key: chain for chain in (*stitching.top, *stitching.top_cross_layer)}
    rooms = {room.chain: room for room in store.load(Headroom, HEADROOM).chains} if store.has(HEADROOM) else {}
    across = [key for key in stitching.keys
              if key in kept and kept[key].stitched_only and kept[key].crosses_layers and kept[key].terminal]
    roomy = [key for key in across if key in rooms and rooms[key].room]
    found = [(rank, key) for rank, key in enumerate(stitching.keys, 1)
             if key.startswith(f"[{first}") and key.endswith(last) and all(text in key for text in through)]
    typer.echo(f"{len(found)} of {len(stitching.keys)} chains match; {len(stitching.top)} kept in full by rank")
    for rank, key in found[:shown]:
        chain = kept.get(key)
        places = ["not kept"] if chain is None else [
            str(chain.visibility), *([f"cross-layer {across.index(key) + 1}"] if key in across else []),
            *([f"headroom {'yes' if rooms[key].room else 'no'}"] if key in rooms else []),
            *([f"cross-layer with headroom {roomy.index(key) + 1}"] if key in roomy else [])]
        typer.echo(f"#{rank} ({', '.join(places)}) condition {chain.condition if chain else '-'}: {key}")


@app.command("validate")
def validate_command(experiment: Experiment,
                     runs: Annotated[int, typer.Option(help="Validation runs the ranked chains choose.")] = 10,
                     batch: Annotated[int, typer.Option(
                         help="Runs chosen at once, before their checks update the chances that rank the "
                              "candidates.")] = 5,
                     per_group: Annotated[int, typer.Option(help="Most runs one group of chains chooses.")] = 3,
                     single_scenario_cross_layer: Annotated[int, typer.Option(
                         help="Best chains across layers one scenario showed, validated as controls.")] = 3,
                     chain: Annotated[list[str], typer.Option(help="A chain to validate besides, by its key.")] = []
                     ) -> None:
    """Validate in batches of runs. A run injects the first fault of the chain that chose it in the workload its
    conditions merge into, and decides every kept chain with the same first fault and workload. The candidates are
    the stitched-only chains across layers ending in a failure the user sees whose count hops have headroom and that
    no natural witness contradicts; every batch's checks update the chances that rank the next batch's runs."""
    store = Store(experiment)
    stitching = store.load(Stitching, chains_file(Strategy.PHASED))
    runner = recorded_runner(store)
    scenarios = recorded_scenarios(store, runner.system)
    order = {key: rank for rank, key in enumerate(stitching.keys)}
    kept = sorted({kept.key: kept for kept in (*stitching.top, *stitching.top_cross_layer)}.values(),
                  key=lambda kept: order[kept.key])
    room = headroom(runner, kept, list(store.load(EdgeSet, edges_file(Strategy.PHASED)).edges), scenarios,
                    stitching.min_count_increase)
    store.save(room, HEADROOM)
    roomy = frozenset(chain_room.chain for chain_room in room.chains if chain_room.room)
    across = [kept_chain for kept_chain in kept if kept_chain.crosses_layers and kept_chain.terminal
              and kept_chain.key in roomy]
    candidates = [kept_chain for kept_chain in across if kept_chain.stitched_only and not kept_chain.contradicted]
    by_key = {kept_chain.key: kept_chain for kept_chain in kept}
    besides = ([(kept_chain, Selection.SINGLE_SCENARIO_CROSS_LAYER) for kept_chain in across
                if kept_chain.shown][:single_scenario_cross_layer] + [(by_key[key], Selection.NAMED) for key in chain])
    validations = list(store.load(Validations, VALIDATIONS).validations) if store.has(VALIDATIONS) else []
    feedback = store.load(MappingFeedback, MAPPING_FEEDBACK) if store.has(MAPPING_FEEDBACK) \
        else MappingFeedback(checks=())
    for start in range(0, runs, batch):
        picks = chosen_runs(candidates, scenarios, feedback.class_checks(), min(batch, runs - start), per_group,
                            {(validation.record.fault.key, validation.workload.name) for validation in validations},
                            Counter(validation.chain.group for validation in validations
                                    if validation.selection == Selection.CROSS_LAYER))
        chosen = validate(runner, [(pick, Selection.CROSS_LAYER) for pick in picks] + (besides if start == 0 else []),
                          scenarios, stitching.min_count_increase).validations
        decided = adjudications(Validations(validations=(*validations, *chosen)), kept, scenarios,
                                stitching.min_count_increase)
        validations += [*chosen, *decided]
        feedback = feedback.merged(mapping_checks(Validations(validations=(*chosen, *decided))))
        store.save(Validations(validations=tuple(validations)), VALIDATIONS)
        store.save(feedback, MAPPING_FEEDBACK)
    for validation in validations:
        if validation.selection != Selection.ADJUDICATED:
            witness = f" contradicted at hops {list(validation.chain.contradicted)}" if validation.chain.contradicted \
                else ""
            hops = "".join("+" if hop.confirmed else "-" for hop in validation.hops)
            typer.echo(f"{'confirmed' if validation.confirmed else 'refuted'} {validation.selection} in "
                       f"{validation.workload.name}: {hops}{witness} {validation.chain.key}")
    for label, members in (("ranked", [validation for validation in validations
                                       if validation.selection == Selection.CROSS_LAYER]),
                           ("adjudicated by run, stitched-only across layers to the user",
                            [validation for validation in validations if validation.selection == Selection.ADJUDICATED
                             and validation.chain.stitched_only and validation.chain.crosses_layers
                             and validation.chain.terminal]),
                           ("adjudicated by run, all", [validation for validation in validations
                                                        if validation.selection == Selection.ADJUDICATED])):
        typer.echo(f"{label}: {sum(validation.confirmed for validation in members)} of {len(members)} confirmed")


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
