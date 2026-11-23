import argparse
import json
from collections import defaultdict
from functools import cached_property
from pathlib import Path

from faultpoint.observations import ObservationRecord
from faultpoint.rules import Rule
from faultpoint.tools.kinds import KindTable
from pydantic import BaseModel, Field

from faultsearch.allocation import Allocation, Assignment, Phase, Strategy, allocation_of
from faultsearch.catalog import (
    FOLLOWING_SEPARATOR,
    FROZEN,
    ActionTable,
    Catalog,
    Fault,
    Following,
    RpcPeers,
    build_catalog,
    control_executions,
    point_layer,
    point_manifests,
    point_scoped,
)
from faultsearch.chains import Stitcher, Stitching
from faultsearch.counterfactual import (
    ControlRecord,
    Group,
    Repetitions,
    Statuses,
    TreatmentRecord,
    tenant_names,
)
from faultsearch.edges import Acceptance, Edge, EffectMap
from faultsearch.evidence import MappingFeedback
from faultsearch.facts import (
    CONTROL_GROUP,
    Facts,
    LoadVariants,
    PointInventory,
    Purpose,
    SearchRun,
    SystemTopology,
    read_facts,
)
from faultsearch.natural import NaturalJudgement, natural_judgements
from faultsearch.validation import (
    Headroom,
    Validation,
    Validations,
    adjudications,
    headroom,
    hop_checks,
    mapping_checks,
    merged_workload,
    merged_workloads,
)


class ComputeSettings(BaseModel):
    """What a graph is computed with besides the facts: how substitute runs are compared, the thresholds of an effect,
    the beam and the clusters. The commit of faultsearch that computes it fixes the rest: the faultpoint analysis
    library, the effect map, the action table and the kind table."""

    model_config = FROZEN

    acceptance: Acceptance = Acceptance.BEHAVIOUR
    alpha: float = 0.1
    min_count_increase: float = 0.2
    min_mean_increase: float = 0.5
    width: int = 20000
    max_hops: int = 4
    kept: int = 2000
    cluster_distance: float = 0.5


def print_settings_schema() -> None:
    """Print the JSON Schema of the compute settings, which a caller passes as a JSON file."""
    print(json.dumps(ComputeSettings.model_json_schema(), indent=2))


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
    natural: tuple[NaturalJudgement, ...] = Field(default=(), exclude_if=lambda runs: not runs)


class InventoryGraph(BaseModel):
    model_config = FROZEN

    inventory: str
    graph: PropagationGraph


class PropagationGraphs(BaseModel):
    """The independently measured graphs of every standing inventory, without implicit cross-inventory identity."""

    model_config = FROZEN

    settings: ComputeSettings
    through: int
    inventories: tuple[InventoryGraph, ...]


class FactRepetitions(Repetitions):
    """The search runs a comparison reads, by recorded identity, retaining their original experiments."""

    def __init__(self, runs: list[SearchRun], settings: ComputeSettings) -> None:
        super().__init__(settings.alpha, settings.min_mean_increase)
        self.runs: dict[str, SearchRun] = {}
        for run in runs:
            if run.identity in self.runs:
                raise ValueError(f"two search runs have the identity {run.identity}")
            self.runs[run.identity] = run
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

    def experiment(self, label: str) -> str:
        return self.runs[label].label


def control_records(runs: list[SearchRun]) -> dict[str, ControlRecord]:
    """The control runs of every workload, by its name, in the order of their indexes."""
    by_workload: dict[str, list[SearchRun]] = defaultdict(list)
    for run in runs:
        if run.group == CONTROL_GROUP:
            by_workload[run.workload.name].append(run)
    for name, controls in by_workload.items():
        if any(run.context != controls[0].context or run.workload != controls[0].workload for run in controls):
            raise ValueError(f"controls of {name} must share an execution context and workload")
    return {name: ControlRecord(workload=controls[0].workload,
                                labels=tuple(run.identity for run in sorted(controls, key=lambda run: run.index)),
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
        if any(run.context != first.context or run.workload != first.workload for run in members):
            raise ValueError(f"treatment group {digest} must share an execution context and workload")
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
        if group.workload.name not in controls:
            continue
        control = controls[group.workload.name]
        if control.workload != group.workload or any(
                repetitions.runs[identity].context != members[0].context for identity in control.labels):
            raise ValueError(f"treatment group {group.digest} does not match its controls' execution context and workload")
        found = repetitions.group_records(group, control.labels, [run.identity for run in members])
        if len(group.faults) > 1 and found[0].leakage:
            continue
        phases: tuple[Phase | None, ...] = members[0].phases or tuple(None for _ in group.faults)
        for record, phase in zip(found, phases, strict=True):
            records.setdefault((record.fault.key, group.workload.name), (record, phase))
    return records


def edge_assignments(groups: list[tuple[Group, list[SearchRun]]],
                     records: dict[tuple[str, str], tuple[TreatmentRecord, Phase | None]]) -> list[Assignment]:
    """The load variant runs as the allocation's assignments: every fault and workload with a record, in the order
    its first group ran, with the phase its run recorded; a fault only a leaking group ran has no record yet."""
    pairs = dict.fromkeys((fault.key, group.workload.name) for group, _ in groups for fault in group.faults
                          if (fault.key, group.workload.name) in records)
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
        if scenario.name not in controls:
            continue
        control = controls[scenario.name]
        labels = [label for label in control.labels if label in listed or repetitions.experiment(label) in listed]
        executions[scenario.name] = control_executions(
            [record for label in labels for record in repetitions.observations(label)], len(labels),
            len(tenant_names(control.workload.workload)), kinds, topology.upstream)
    return build_catalog(inventory.manifests, executions, list(inventory.configured), ActionTable.read(), kinds,
                         topology.upstream)


def judged(stitching: Stitching, edges: list[Edge], path_runs: list[tuple[Group, list[SearchRun]]],
           controls: dict[str, ControlRecord], repetitions: FactRepetitions, variants: LoadVariants,
           settings: ComputeSettings) -> tuple[tuple[TreatmentRecord, ...], Headroom, Validations]:
    """The path runs' records, the headroom of the kept chains, and the judgement of the chains the path runs were
    asked for, then of every other kept chain one of those runs decides. Only a merged workload with control runs
    compares: a kept chain whose workload has none yet has no headroom, and a path run in such a workload judges
    nothing, so the chains it would check still need a run; a path run asked for by a chain no longer kept judges
    only the kept chains it decides."""
    scenarios = variants.scenarios
    order = {key: rank for rank, key in enumerate(stitching.keys)}
    kept = sorted({chain.key: chain for chain in (*stitching.top, *stitching.top_cross_layer)}.values(),
                  key=lambda chain: order[chain.key])
    by_key = {chain.key: chain for chain in kept}
    controlled = [chain for chain in kept if merged_workload(chain.condition, scenarios).name in controls]
    room = headroom(controlled, edges, scenarios, settings.min_count_increase,
                    [controls[workload.name] for workload in merged_workloads(controlled, scenarios)], repetitions)
    records = []
    requested = []
    for group, members in path_runs:
        if group.workload.name not in controls:
            continue
        if controls[group.workload.name].workload != group.workload:
            raise ValueError(f"path group {group.digest} does not match its controls' workload")
        record = repetitions.group_records(group, controls[group.workload.name].labels,
                                           [run.identity for run in members])[0]
        records.append(record)
        requested += [Validation(chain=by_key[request.chain], selection=request.selection,
                                 workload=merged_workload(by_key[request.chain].condition, scenarios), record=record,
                                 hops=hop_checks(by_key[request.chain], record, settings.min_count_increase))
                      for request in members[0].requests if request.chain in by_key]
    decided = adjudications(Validations(validations=tuple(requested)), kept, scenarios, settings.min_count_increase)
    return tuple(records), room, Validations(validations=(*requested, *decided))


class FactGraph:
    """The graph the facts give under the settings, each part computed when it is first read, so that planning reads
    only what the facts so far allow. Edges come only from the runs in load variants; the merged workloads only judge
    paths and measure headroom."""

    def __init__(self, facts: Facts, settings: ComputeSettings, inventory: PointInventory) -> None:
        self.facts = facts
        self.settings = settings
        declared = Facts(facts=tuple(fact for fact in facts.facts if fact.sequence <= inventory.sequence))
        self.topology = declared.latest(SystemTopology)
        self.variants = declared.latest(LoadVariants)
        self.kinds = KindTable.installed()
        self.inventory = inventory
        named = facts.inventory_controls(inventory)
        self.context = named[0].context
        self.runs = [run for run in facts.standing_runs() if run.purpose != Purpose.NATURAL
                     and run.context == self.context]
        self.repetitions = FactRepetitions(self.runs, settings)
        self.controls = control_records(self.runs)

    @cached_property
    def catalog(self) -> Catalog:
        return graph_catalog(self.controls, self.inventory, self.topology, self.variants, self.repetitions,
                             self.kinds)

    @cached_property
    def edge_groups(self) -> list[tuple[Group, list[SearchRun]]]:
        return treatment_groups(self.runs, Purpose.EDGE, self.topology, self.kinds)

    @cached_property
    def phased_records(self) -> dict[tuple[str, str], tuple[TreatmentRecord, Phase | None]]:
        return group_treatments(self.edge_groups, self.controls, self.repetitions)

    @cached_property
    def assignments(self) -> list[Assignment]:
        return edge_assignments(self.edge_groups, self.phased_records)

    @cached_property
    def by_pair(self) -> dict[tuple[str, str], TreatmentRecord]:
        """Every load variant's treatment record, by fault key and workload."""
        return {pair: record for pair, (record, _) in self.phased_records.items()}

    @cached_property
    def allocation(self) -> Allocation:
        strategy = Strategy.RANDOM if any(assignment.phase == Phase.RANDOM for assignment in self.assignments) \
            else Strategy.PHASED
        return allocation_of(strategy, self.assignments, self.by_pair, self.settings.cluster_distance)

    @cached_property
    def records(self) -> list[TreatmentRecord]:
        """The treatment records in the order of the assignments."""
        return [self.by_pair[(assignment.fault.key, assignment.scenario)] for assignment in self.assignments]

    @cached_property
    def stitcher(self) -> Stitcher:
        settings = self.settings
        return Stitcher(scenarios=self.variants.scenarios,
                        effects=EffectMap.read(self.topology.entry_service).model_copy(
                            update={"terminal_outcomes": self.topology.terminal_outcomes,
                                    "terminal_kinds": self.topology.terminal_kinds}),
                        catalog=self.catalog, kinds=self.kinds, upstream=self.topology.upstream,
                        targets=self.topology.targets,
                        peers=RpcPeers(ports=self.topology.ports, hosts=self.topology.hosts),
                        manifests=point_manifests(self.inventory.manifests),
                        min_count_increase=settings.min_count_increase, min_mean_increase=settings.min_mean_increase,
                        acceptance=settings.acceptance, width=settings.width, max_hops=settings.max_hops,
                        kept=settings.kept)

    @cached_property
    def edges(self) -> list[Edge]:
        return self.stitcher.edges(self.records)

    @cached_property
    def stitching(self) -> Stitching:
        """The chains stitched without any path judgement."""
        return self.stitcher.chains(self.edges, self.allocation, self.records, MappingFeedback(checks=()))

    @cached_property
    def judgement(self) -> tuple[tuple[TreatmentRecord, ...], Headroom, Validations]:
        return judged(self.stitching, self.edges, treatment_groups(self.runs, Purpose.PATH, self.topology, self.kinds),
                      self.controls, self.repetitions, self.variants, self.settings)

    @cached_property
    def feedback(self) -> MappingFeedback:
        return MappingFeedback(checks=()).merged(mapping_checks(self.judgement[2]))

    @cached_property
    def judged_stitching(self) -> Stitching:
        """The chains stitched again with what the path runs confirmed and refuted."""
        return self.stitcher.chains(self.edges, self.allocation, self.records, self.feedback)

    @cached_property
    def natural(self) -> tuple[NaturalJudgement, ...]:
        return natural_judgements(self.facts, self.judged_stitching, self.inventory,
                                  self.settings.alpha, self.settings.min_mean_increase,
                                  self.settings.min_count_increase)

    def graph(self) -> PropagationGraph:
        path_records, room, validations = self.judgement
        return PropagationGraph(
            settings=self.settings, through=self.facts.facts[-1].sequence, catalog=self.catalog,
            controls=tuple(self.controls.values()), records=tuple(self.records), allocation=self.allocation,
            edges=tuple(self.edges), stitching=self.stitching, path_records=path_records, headroom=room,
            validations=validations, feedback=self.feedback, judged_stitching=self.judged_stitching,
            natural=self.natural)


def compute_graph(facts: Facts, settings: ComputeSettings) -> PropagationGraphs:
    return PropagationGraphs(settings=settings, through=facts.facts[-1].sequence if facts.facts else 0,
        inventories=tuple(InventoryGraph(inventory=inventory.identity,
            graph=FactGraph(facts, settings, inventory).graph()) for inventory in facts.inventories()))


def print_graph() -> None:
    parser = argparse.ArgumentParser(description="Compute every standing inventory's graph from its recorded evidence.")
    parser.add_argument("facts", type=Path)
    parser.add_argument("settings", type=Path)
    arguments = parser.parse_args()
    print(compute_graph(read_facts(arguments.facts), ComputeSettings.model_validate_json(
        arguments.settings.read_bytes())).model_dump_json())


def print_graph_schema() -> None:
    print(json.dumps(PropagationGraphs.model_json_schema(), indent=2))
