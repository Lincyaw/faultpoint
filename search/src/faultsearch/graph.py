from collections import defaultdict
from importlib.metadata import version

from faultpoint.observations import ObservationRecord
from faultpoint.rules import Rule
from faultpoint.tools.kinds import KindTable
from pydantic import BaseModel

from faultsearch.allocation import Allocation, Assignment, Phase, Strategy, allocation_of
from faultsearch.catalog import (FOLLOWING_SEPARATOR, FROZEN, ActionTable, Catalog, Fault, Following, build_catalog,
                                 control_executions, point_layer, point_manifests, point_scoped)
from faultsearch.chains import Stitcher, Stitching
from faultsearch.counterfactual import ControlRecord, Group, Repetitions, Statuses, TreatmentRecord, tenant_names
from faultsearch.edges import Acceptance, Edge, EffectMap
from faultsearch.evidence import MappingFeedback
from faultsearch.facts import CONTROL_GROUP, Facts, LoadVariants, PointInventory, Purpose, SearchRun, SystemTopology
from faultsearch.validation import (Headroom, Validation, Validations, adjudications, headroom, hop_checks,
                                    mapping_checks, merged_workload, merged_workloads)


class ComputeSettings(BaseModel):
    """What a graph is computed with besides the facts: how substitute runs are compared, the thresholds of an effect,
    the beam, the clusters, and the versions of faultsearch and of the faultpoint analysis library, which fix the effect
    map, the action table and the kind table."""

    model_config = FROZEN

    acceptance: Acceptance = Acceptance.BEHAVIOUR
    alpha: float = 0.1
    min_count_increase: float = 0.2
    min_mean_increase: float = 0.5
    width: int = 20000
    max_hops: int = 4
    kept: int = 2000
    cluster_distance: float = 0.5
    faultsearch: str
    faultpoint: str


def installed_settings() -> ComputeSettings:
    """The default settings of the installed faultsearch and faultpoint."""
    return ComputeSettings(faultsearch=version("faultsearch"), faultpoint=version("faultpoint"))


class PropagationGraph(BaseModel):
    """What the facts up to one sequence number give under one set of settings: the fault catalog, the controls and
    treatment records of the load variants, the allocation and the edges they give, the chains stitched without any
    path judgement, the path runs' records, the headroom and the judgement of the kept chains, and the chains stitched
    again with that judgement."""

    model_config = FROZEN

    settings: ComputeSettings
    through: int
    catalog: Catalog
    controls: tuple[ControlRecord, ...]
    records: tuple[TreatmentRecord, ...]
    allocation: Allocation
    edges: tuple[Edge, ...]
    stitching: Stitching
    path_records: tuple[TreatmentRecord, ...]
    headroom: Headroom
    validations: Validations
    feedback: MappingFeedback
    judged_stitching: Stitching


class FactRepetitions(Repetitions):
    """The search runs of the facts as the repetitions a comparison reads, by label."""

    def __init__(self, runs: list[SearchRun], settings: ComputeSettings) -> None:
        super().__init__(settings.alpha, settings.min_mean_increase)
        self.runs: dict[str, SearchRun] = {}
        for run in runs:
            if run.label in self.runs:
                raise ValueError(f"two search runs have the label {run.label}")
            self.runs[run.label] = run
        self.cache: dict[str, list[ObservationRecord]] = {}

    def observations(self, label: str) -> list[ObservationRecord]:
        if label not in self.cache:
            self.cache[label] = self.runs[label].records()
        return self.cache[label]

    def statuses(self, label: str) -> Statuses:
        return self.runs[label].statuses

    def seed(self, label: str) -> int:
        return self.runs[label].seed

    def refusal(self, label: str) -> str | None:
        return self.runs[label].refusal


def control_records(runs: list[SearchRun]) -> dict[str, ControlRecord]:
    """The control runs of every workload, by its name, in the order of their indexes."""
    by_workload: dict[str, list[SearchRun]] = defaultdict(list)
    for run in runs:
        if run.group == CONTROL_GROUP:
            by_workload[run.workload.name].append(run)
    return {name: ControlRecord(workload=controls[0].workload,
                                labels=tuple(run.label for run in sorted(controls, key=lambda run: run.index)),
                                statuses=tuple(run.statuses for run in sorted(controls, key=lambda run: run.index)))
            for name, controls in by_workload.items()}


def intervention_faults(rules: tuple[Rule, ...], topology: SystemTopology, kinds: KindTable) -> tuple[Fault, ...]:
    """The faults an intervention injects, rebuilt from its rules: a fault's own rule carries its digest as id, and
    each rule after it the digest and its index; a rebuilt fault whose digest is not its rule's is an error."""
    by_fault: dict[str, list[Rule]] = defaultdict(list)
    for rule in rules:
        by_fault[rule.id.partition(FOLLOWING_SEPARATOR)[0]].append(rule)
    faults = []
    for digest, (own, *following) in by_fault.items():
        layer = point_layer(own.point, topology.upstream)
        fault = Fault(point=own.point, action=own.action, layer=layer, scoped=point_scoped(own.point, layer, kinds),
                      probability=own.trigger.probability,
                      following=tuple(Following(action=rule.action, probability=rule.trigger.probability)
                                      for rule in following))
        if fault.digest != digest:
            raise ValueError(f"the rule {own.id} at {own.point} stands for {fault.key}, whose digest is {fault.digest}")
        faults.append(fault)
    return tuple(faults)


def treatment_groups(runs: list[SearchRun], purpose: Purpose, topology: SystemTopology,
                     kinds: KindTable) -> list[tuple[Group, list[SearchRun]]]:
    """The groups the treatment runs of one purpose ran, with their runs by index, in the order each group first
    ran; a group whose rebuilt digest is not the runs' is an error."""
    by_group: dict[tuple[str, str, str], list[SearchRun]] = defaultdict(list)
    for run in runs:
        if run.purpose == purpose and run.group != CONTROL_GROUP:
            by_group[(run.source, run.workload.name, run.group)].append(run)
    groups = []
    for (_, _, digest), members in by_group.items():
        first = members[0]
        group = Group(workload=first.workload, faults=intervention_faults(first.rules, topology, kinds))
        if group.digest != digest:
            raise ValueError(f"the runs of group {digest} in {first.workload.name} inject a group whose digest is "
                             f"{group.digest}")
        groups.append((group, sorted(members, key=lambda run: run.index)))
    return groups


def group_treatments(groups: list[tuple[Group, list[SearchRun]]], controls: dict[str, ControlRecord],
                     repetitions: FactRepetitions) -> dict[tuple[str, str], tuple[TreatmentRecord, Phase | None]]:
    """Every fault's record in every workload, from the first group of its that did not leak into an untreated
    tenant, with the phase the group's run gave it; a fault in a packed group that leaked has its record from the run
    where it was alone."""
    records: dict[tuple[str, str], tuple[TreatmentRecord, Phase | None]] = {}
    for group, members in groups:
        found = repetitions.group_records(group, controls[group.workload.name].labels, [run.label for run in members])
        if len(group.faults) > 1 and found[0].leakage:
            continue
        phases = members[0].phases or tuple(None for _ in group.faults)
        for record, phase in zip(found, phases, strict=True):
            records.setdefault((record.fault.key, group.workload.name), (record, phase))
    return records


def edge_assignments(groups: list[tuple[Group, list[SearchRun]]],
                     records: dict[tuple[str, str], tuple[TreatmentRecord, Phase | None]]) -> list[Assignment]:
    """The load variant runs as the allocation's assignments: every fault and workload in the order its first group
    ran, with the phase its run recorded."""
    pairs = dict.fromkeys((fault.key, group.workload.name) for group, _ in groups for fault in group.faults)
    assignments = []
    for key, workload in pairs:
        record, phase = records[(key, workload)]
        if phase is None:
            raise ValueError(f"the edge run of {key} in {workload} recorded no allocation phase")
        assignments.append(Assignment(fault=record.fault, scenario=workload, phase=phase))
    return assignments


def graph_catalog(controls: dict[str, ControlRecord], inventory: PointInventory, topology: SystemTopology,
                  variants: LoadVariants, repetitions: FactRepetitions, kinds: KindTable) -> Catalog:
    """The catalog over the inventory's manifests and configured points and the points its control runs observed in
    every load variant."""
    listed = set(inventory.controls)
    executions = {}
    for scenario in variants.scenarios.scenarios:
        control = controls[scenario.name]
        labels = [label for label in control.labels if label in listed]
        executions[scenario.name] = control_executions(
            [record for label in labels for record in repetitions.observations(label)], len(labels),
            len(tenant_names(control.workload.workload)), kinds, topology.upstream)
    return build_catalog(inventory.manifests, executions, list(inventory.configured), ActionTable.read(), kinds,
                         topology.upstream)


def judged(stitching: Stitching, edges: list[Edge], path_runs: list[tuple[Group, list[SearchRun]]],
           controls: dict[str, ControlRecord], repetitions: FactRepetitions, variants: LoadVariants,
           settings: ComputeSettings) -> tuple[tuple[TreatmentRecord, ...], Headroom, Validations]:
    """The path runs' records, the headroom of the kept chains, and the judgement of the chains the path runs were
    asked for, then of every other kept chain one of those runs decides."""
    scenarios = variants.scenarios
    order = {key: rank for rank, key in enumerate(stitching.keys)}
    kept = sorted({chain.key: chain for chain in (*stitching.top, *stitching.top_cross_layer)}.values(),
                  key=lambda chain: order[chain.key])
    by_key = {chain.key: chain for chain in kept}
    room = headroom(kept, edges, scenarios, settings.min_count_increase,
                    [controls[workload.name] for workload in merged_workloads(kept, scenarios)], repetitions)
    records = []
    requested = []
    for group, members in path_runs:
        record = repetitions.group_records(group, controls[group.workload.name].labels,
                                           [run.label for run in members])[0]
        records.append(record)
        requested += [Validation(chain=by_key[request.chain], selection=request.selection,
                                 workload=merged_workload(by_key[request.chain].condition, scenarios), record=record,
                                 hops=hop_checks(by_key[request.chain], record, settings.min_count_increase))
                      for request in members[0].requests]
    decided = adjudications(Validations(validations=tuple(requested)), kept, scenarios, settings.min_count_increase)
    return tuple(records), room, Validations(validations=(*requested, *decided))


def compute_graph(facts: Facts, settings: ComputeSettings) -> PropagationGraph:
    """The graph the facts give under the settings, which must be those of the installed faultsearch and faultpoint:
    edges only from the runs in load variants, the merged workloads only judging paths and measuring headroom."""
    installed = installed_settings()
    if (settings.faultsearch, settings.faultpoint) != (installed.faultsearch, installed.faultpoint):
        raise ValueError(f"the settings are for faultsearch {settings.faultsearch} and faultpoint {settings.faultpoint}, "
                         f"but {installed.faultsearch} and {installed.faultpoint} are installed")
    topology = facts.latest(SystemTopology)
    variants = facts.latest(LoadVariants)
    inventory = facts.latest(PointInventory)
    kinds = KindTable.installed()
    runs = facts.standing_runs()
    repetitions = FactRepetitions(runs, settings)
    controls = control_records(runs)
    catalog = graph_catalog(controls, inventory, topology, variants, repetitions, kinds)
    edge_groups = treatment_groups(runs, Purpose.EDGE, topology, kinds)
    records = group_treatments(edge_groups, controls, repetitions)
    assignments = edge_assignments(edge_groups, records)
    by_pair = {pair: record for pair, (record, _) in records.items()}
    allocation = allocation_of(Strategy.RANDOM if any(assignment.phase == Phase.RANDOM for assignment in assignments)
                               else Strategy.PHASED, assignments, by_pair, settings.cluster_distance)
    ordered = [by_pair[(assignment.fault.key, assignment.scenario)] for assignment in assignments]
    stitcher = Stitcher(scenarios=variants.scenarios,
                        effects=EffectMap.read(topology.entry_service).model_copy(
                            update={"terminal_outcomes": topology.terminal_outcomes}),
                        catalog=catalog, kinds=kinds, upstream=topology.upstream, targets=topology.targets,
                        services={port: service for service, port in topology.ports.items()},
                        manifests=point_manifests(inventory.manifests), min_count_increase=settings.min_count_increase,
                        min_mean_increase=settings.min_mean_increase, acceptance=settings.acceptance,
                        width=settings.width, max_hops=settings.max_hops, kept=settings.kept)
    edges = stitcher.edges(ordered)
    stitching = stitcher.chains(edges, allocation, ordered, MappingFeedback(checks=()))
    path_records, room, validations = judged(stitching, edges, treatment_groups(runs, Purpose.PATH, topology, kinds),
                                             controls, repetitions, variants, settings)
    feedback = MappingFeedback(checks=()).merged(mapping_checks(validations))
    return PropagationGraph(settings=settings, through=facts.facts[-1].sequence, catalog=catalog,
                            controls=tuple(controls.values()), records=tuple(ordered), allocation=allocation,
                            edges=tuple(edges), stitching=stitching, path_records=path_records, headroom=room,
                            validations=validations, feedback=feedback,
                            judged_stitching=stitcher.chains(edges, allocation, ordered, feedback))
