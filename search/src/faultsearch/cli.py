import math
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
from faultsearch.budget import BUDGETS, Plan, Trajectory, budget_table, simulate
from faultsearch.catalog import (FROZEN, ActionTable, Catalog, Fault, build_catalog, control_executions, point_layer,
                                 point_manifests, point_scoped)
from faultsearch.chains import Stitcher, Stitching
from faultsearch.counterfactual import (EffectKey, NamedWorkload, Runner, RunSettings, Scenarios, tenant_names,
                                        treatment_record)
from faultsearch.edges import Acceptance, Condition, EdgeSet, EffectMap, counterpart_assignments, holds
from faultsearch.refill import candidate_phase
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
MaxLoad = Annotated[float, typer.Option(
    help="The host's 1-minute load above which no new repetition starts while others still run.")]
WIDTH: Final = 20000
"""The partial chains the beam keeps at every length."""
MAX_HOPS: Final = 4
MIN_COUNT_INCREASE: Final = 0.2
"""The smallest relative increase of a count that counts as an effect."""
EVERY_CHAIN: Final = 10**6
"""Chains written in full when the candidate phase continues every stitched chain."""


def services_by_port(system: System) -> dict[int, str]:
    return {port: service for service, port in system.ports.items()}


def recorded_system(store: Store) -> System:
    return SYSTEMS[store.load(RunSettings, RUN_SETTINGS).system]


def recorded_scenarios(store: Store, system: System) -> Scenarios:
    return store.record_input(Scenarios.read(system.scenarios), INPUTS, SCENARIOS_INPUT)


def recorded_runner(store: Store, max_load: float) -> Runner:
    settings = store.load(RunSettings, RUN_SETTINGS)
    system = SYSTEMS[settings.system]
    if system.verified_build(settings.sdk) != settings.commit:
        raise RuntimeError(f"the services are not built from {settings.commit}")
    return Runner(store, settings, system, max_load)


def recorded_stitcher(store: Store, system: System, min_count_increase: float, acceptance: Acceptance, width: int,
                      max_hops: int, kept: int) -> Stitcher:
    return Stitcher(scenarios=recorded_scenarios(store, system),
                    effects=store.record_input(EffectMap.read(system.entry_service), INPUTS, EFFECTS_INPUT),
                    catalog=store.load(Catalog, CATALOG), kinds=KindTable.installed(), upstream=UPSTREAM_SERVICES,
                    targets=UNSCOPED_TARGETS, services=services_by_port(system),
                    manifests=point_manifests(system.manifests), min_count_increase=min_count_increase,
                    min_mean_increase=store.load(RunSettings, RUN_SETTINGS).min_mean_increase, acceptance=acceptance,
                    width=width, max_hops=max_hops, kept=kept)


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
            rebuild: Rebuild = False, system: Explored = SHOP.name, max_load: MaxLoad = math.inf) -> None:
    """Run the controls of every scenario, build the fault catalog, and spend the budget with one strategy."""
    store = Store(experiment)
    sdk = sdk_root.resolve()
    explored = SYSTEMS[system]
    commit = explored.build(sdk) if rebuild else explored.verified_build(sdk)
    runner = Runner(store, store.record_input(RunSettings(
        sdk=sdk, commit=commit, repetitions=repetitions, alpha=alpha, min_mean_increase=min_mean_increase,
        workers=workers, pack_tenants=pack_tenants, system=system), RUN_SETTINGS), explored, max_load)
    exploration = catalog_exploration(store, runner, AllocationSettings(
        budget=budget, seed=seed, round_robin_share=round_robin_share, cluster_distance=cluster_distance,
        epsilon=epsilon, batch=batch))
    allocation = phased_allocation(exploration) if strategy == Strategy.PHASED else random_allocation(exploration)
    store.save(allocation, allocation_file(strategy))
    typer.echo(f"{strategy}: {len(allocation.assignments)} injections, {len(allocation.clusters)} clusters")


@app.command()
def replay(experiment: Experiment,
           source: Annotated[str, typer.Option(help="The experiment whose phased assignments to run again.")],
           sdk_root: SdkRoot, rebuild: Rebuild = False, max_load: MaxLoad = math.inf) -> None:
    """Run another experiment's phased assignments again with another SDK build, under that experiment's scenarios
    and settings, then every fault of the catalog they leave out once, such as those of a new fault source."""
    store = Store(experiment)
    recorded = Store(source)
    sdk = sdk_root.resolve()
    system = recorded_system(recorded)
    commit = system.build(sdk) if rebuild else system.verified_build(sdk)
    runner = Runner(store, store.record_input(recorded.load(RunSettings, RUN_SETTINGS).model_copy(
        update={"sdk": sdk, "commit": commit}), RUN_SETTINGS), system, max_load)
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
                   width: Annotated[int, typer.Option(help="Partial chains kept at every length.")] = WIDTH,
                   max_hops: int = MAX_HOPS,
                   kept: Annotated[int, typer.Option(help="Ranked chains written in full.")] = 300,
                   min_count_increase: Annotated[float, typer.Option(
                       help="The smallest relative increase of a count that counts as an effect.")] = MIN_COUNT_INCREASE,
                   acceptance: Annotated[Acceptance, typer.Option(
                       help="How a substitute run is compared with the natural run it stands for.")]
                   = Acceptance.BEHAVIOUR) -> None:
    """Learn the edges of a strategy's injections and stitch them into ranked chains and cycles, leaving out the
    steps from an effect through a counterpart to a consequence that validations refuted."""
    store = Store(experiment)
    stitcher = recorded_stitcher(store, recorded_system(store), min_count_increase, acceptance, width, max_hops, kept)
    allocation = store.load(Allocation, allocation_file(strategy))
    records = [treatment_record(store, assignment.fault, assignment.scenario) for assignment in allocation.assignments]
    edges = stitcher.edges(records)
    store.save(EdgeSet(strategy=strategy, edges=tuple(edges), acceptance=acceptance), edges_file(strategy))
    feedback = store.load(MappingFeedback, MAPPING_FEEDBACK) if store.has(MAPPING_FEEDBACK) \
        else MappingFeedback(checks=())
    stitching = stitcher.chains(edges, allocation, records, feedback)
    store.save(stitching, chains_file(strategy))
    needed = counterpart_assignments(edges, {(assignment.fault.key, assignment.scenario)
                                             for assignment in allocation.assignments}, stitcher.catalog)
    typer.echo(f"{strategy}: {len(edges)} edges, {stitching.chains} chains ({stitching.stitched_only} stitched only, "
               f"{stitching.single_scenario} shown end to end by one scenario, {stitching.undetermined} undetermined), "
               f"{len(stitching.cycles)} cycles; {len(needed)} counterpart injections not yet run")


@app.command()
def complete(experiment: Experiment, max_load: MaxLoad = math.inf) -> None:
    """Inject the faults that correspond to the effects of the last stitching's edges in the scenarios that execute
    their points and that no assignment of the phased allocation tried, so that the next stitching continues through
    them."""
    store = Store(experiment)
    allocation = store.load(Allocation, allocation_file(Strategy.PHASED))
    catalog = store.load(Catalog, CATALOG)
    needed = counterpart_assignments(list(store.load(EdgeSet, edges_file(Strategy.PHASED)).edges),
                                     {(assignment.fault.key, assignment.scenario)
                                      for assignment in allocation.assignments}, catalog)
    runner = recorded_runner(store, max_load)
    exploration = Exploration(runner, catalog, recorded_scenarios(store, runner.system),
                              store.load(AllocationSettings, ALLOCATION_SETTINGS))
    completed = extended_allocation(exploration, Strategy.PHASED, [*allocation.assignments, *needed])
    store.save(completed, allocation_file(Strategy.PHASED))
    typer.echo(f"{len(needed)} counterpart injections: {len(completed.assignments)} injections, "
               f"{len(completed.clusters)} clusters")


@app.command()
def focus(experiment: Experiment,
          budget: Annotated[int, typer.Option(help="Counterpart injections the candidate phase may spend.")],
          max_load: MaxLoad = math.inf) -> None:
    """The candidate phase after the phased allocation's assignments: spend a budget of counterpart injections on the
    hypothesised hops of the best candidate chains, by expected information per injection, stitching again after
    every batch."""
    store = Store(experiment)
    runner = recorded_runner(store, max_load)
    stitcher = recorded_stitcher(store, runner.system, MIN_COUNT_INCREASE, Acceptance.BEHAVIOUR, WIDTH, MAX_HOPS,
                                 EVERY_CHAIN)
    exploration = Exploration(runner, stitcher.catalog, stitcher.scenarios,
                              store.load(AllocationSettings, ALLOCATION_SETTINGS))
    exploration.run(list(store.load(Allocation, allocation_file(Strategy.PHASED)).assignments))
    spent = candidate_phase(exploration, budget, Strategy.PHASED, stitcher)
    allocation = exploration.allocation(Strategy.PHASED)
    store.save(allocation, allocation_file(Strategy.PHASED))
    typer.echo(f"candidate phase: {spent} injections; {len(allocation.assignments)} in all")


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
    """Compare allocation plans offline on a full experiment's records, running nothing: every plan, exploring budget
    and seed spends the refill budgets in turn, then stitches and validates from the records alone; a pair the
    records lack is charged and counted. Trajectories already compared are read back; the table shows a target
    chain's ranks among the stitched-only chains across layers ending at the user."""
    store = Store(experiment)
    runner = recorded_runner(store, math.inf)
    stitcher = recorded_stitcher(store, runner.system, MIN_COUNT_INCREASE, Acceptance.BEHAVIOUR, WIDTH, MAX_HOPS,
                                 EVERY_CHAIN)
    settings = store.load(AllocationSettings, ALLOCATION_SETTINGS)
    trajectories = []
    for chosen_plan in plan:
        for budget in explore:
            for chosen_seed in seed:
                name = f"{chosen_plan}-explore{budget}-seed{chosen_seed}.json"
                if not store.has(BUDGETS, name):
                    store.save(simulate(chosen_plan, budget, refill, chosen_seed, runner, settings, stitcher),
                               BUDGETS, name)
                    typer.echo(f"compared {name}")
                trajectory = store.load(Trajectory, BUDGETS, name)
                if [found.refill for found in trajectory.snapshots] != sorted(refill):
                    raise ValueError(f"{name} was compared at other refill budgets")
                trajectories.append(trajectory)
    for line in budget_table(trajectories, lambda key: key.startswith(f"[{first}") and key.endswith(last)
                             and all(text in key for text in through) and hops in (0, key.count(" -> ") + 1),
                             store.load(Allocation, allocation_file(Strategy.PHASED))):
        typer.echo(line)


@app.command()
def rerecord(experiment: Experiment) -> None:
    """Record every injection of the phased allocation again from the repetitions it ran, without running any, so
    that records written before a newer record kept a measure gain it."""
    store = Store(experiment)
    runner = recorded_runner(store, math.inf)
    scenarios = recorded_scenarios(store, runner.system)
    assignments = store.load(Allocation, allocation_file(Strategy.PHASED)).assignments
    runner.rerecord([(assignment.fault, NamedWorkload(name=assignment.scenario,
                                                      workload=scenarios.workload(assignment.scenario)))
                     for assignment in assignments])
    typer.echo(f"{len(assignments)} injections recorded again")


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
                     chain: Annotated[list[str], typer.Option(help="A chain to validate besides, by its key.")] = [],
                     max_load: MaxLoad = math.inf) -> None:
    """Validate in batches of runs. A run injects the first fault of the chain that chose it in the workload its
    conditions merge into, and decides every kept chain with the same first fault and workload. The candidates are
    the stitched-only chains across layers ending in a failure the user sees whose count hops have headroom and that
    no natural witness contradicts; every batch's checks update the chances that rank the next batch's runs."""
    store = Store(experiment)
    stitching = store.load(Stitching, chains_file(Strategy.PHASED))
    runner = recorded_runner(store, max_load)
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
    probability: float = 1.0
    condition: Condition = {}


@app.command()
def trial(experiment: Experiment, sdk_root: SdkRoot,
          trials: Annotated[Path, typer.Option(help="A JSON list of trials: point, action and condition.")],
          system: Explored = SHOP.name, repetitions: int = 3, workers: int = 6, alpha: float = 0.1,
          min_mean_increase: float = 0.5,
          min_count_increase: Annotated[float, typer.Option(
              help="The smallest relative increase of a count that counts as an effect.")] = MIN_COUNT_INCREASE,
          max_load: MaxLoad = math.inf) -> None:
    """Inject given faults alone in given workloads, against controls of those workloads, and show every tenant's
    statuses and every effect: a check of what a constructed system does, before a search explores it."""
    store = Store(experiment)
    explored = SYSTEMS[system]
    runner = Runner(store, store.record_input(RunSettings(
        sdk=sdk_root.resolve(), commit=explored.verified_build(sdk_root.resolve()), repetitions=repetitions,
        alpha=alpha, min_mean_increase=min_mean_increase, workers=workers, pack_tenants=False, system=system),
        RUN_SETTINGS), explored, max_load)
    scenarios = recorded_scenarios(store, explored)
    pairs = [(Fault(point=item.point, action=item.action, layer=point_layer(item.point, UPSTREAM_SERVICES),
                    scoped=point_scoped(item.point, point_layer(item.point, UPSTREAM_SERVICES), runner.kinds),
                    probability=item.probability),
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
