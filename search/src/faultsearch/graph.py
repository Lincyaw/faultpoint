import argparse
import json
from collections import defaultdict
from functools import cached_property
from pathlib import Path
from typing import Final

import numpy as np
from faultpoint.observations import ObservationRecord
from faultpoint.points import PointKind
from faultpoint.rules import Rule
from faultpoint.tools.kinds import KindTable, manifest_violations
from pydantic import BaseModel, Field
from scipy.sparse import coo_array
from scipy.sparse.csgraph import connected_components

from faultsearch.allocation import Allocation, Assignment, Phase, Strategy, allocation_of
from faultsearch.catalog import (
    BOUNDARY_KINDS,
    FOLLOWING_SEPARATOR,
    FROZEN,
    GRPC_METHOD,
    ActionTable,
    Catalog,
    Fault,
    Following,
    RpcPeers,
    build_catalog,
    control_executions,
    point_kind,
    point_layer,
    point_manifests,
    point_scoped,
)
from faultsearch.chains import (
    CROSS_LAYER_KEPT,
    Chain,
    ChainWitness,
    Stitcher,
    Stitching,
    StitchSource,
    StitchSources,
    Witnesses,
    beam_search,
    ranked_chains,
)
from faultsearch.counterfactual import (
    ControlRecord,
    Group,
    Repetitions,
    Statuses,
    TreatmentRecord,
    tenant_names,
)
from faultsearch.edges import ERROR, Acceptance, Edge, EffectMap
from faultsearch.evidence import MappingFeedback
from faultsearch.facts import (
    CONTROL_GROUP,
    Equivalence,
    Facts,
    LoadVariants,
    PathIdentity,
    PointInventory,
    Purpose,
    SearchRun,
    SystemTopology,
    read_facts,
)
from faultsearch.natural import NaturalJudgement, natural_comparisons, natural_judgements
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

GO_LANGUAGE: Final = "go"


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


class EquivalenceGraph(BaseModel):
    """Cross-inventory chains over original measured edges and explicit standing equivalences."""

    model_config = FROZEN

    equivalences: tuple[str, ...]
    edges: tuple[Edge, ...]
    chains: tuple[Chain, ...]
    cycles: tuple[Chain, ...]


class PathTarget(BaseModel):
    """Native executable points at one actual inventory, retaining the chain's original source groups and key."""
    model_config = FROZEN

    inventory: str
    chain: Chain


class PropagationGraphs(BaseModel):
    """The independently measured graphs of every standing inventory, without implicit cross-inventory identity."""

    model_config = FROZEN

    settings: ComputeSettings
    through: int
    inventories: tuple[InventoryGraph, ...]
    equivalence: EquivalenceGraph | None = Field(default=None, exclude_if=lambda graph: graph is None)
    natural: tuple[NaturalJudgement, ...] = Field(default=(), exclude_if=lambda runs: not runs)


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


class EquivalentGraphs:
    """Measured inventory graphs and the explicit point identities that can connect their edges."""

    def __init__(self, facts: Facts, settings: ComputeSettings) -> None:
        self.facts = facts
        self.settings = settings
        self.graphs = {inventory.identity: FactGraph(facts, settings, inventory)
                       for inventory in facts.inventories()}

    @cached_property
    def equivalences(self) -> tuple[Equivalence, ...]:
        voided = self.facts.voided()
        return tuple(fact for fact in self.facts.facts if isinstance(fact, Equivalence)
                     and fact.identity not in voided
                     and fact.left.inventory in self.graphs and fact.right.inventory in self.graphs)

    @cached_property
    def known_points(self) -> dict[str, frozenset[str]]:
        return {identity: frozenset({*graph.catalog.executions, *(fault.point for fault in graph.catalog.faults),
                                    *point_manifests(graph.inventory.manifests), *graph.inventory.configured})
                for identity, graph in self.graphs.items()}

    @cached_property
    def points(self) -> dict[tuple[str, str], tuple[str, str]]:
        references = sorted({(reference.inventory, reference.point) for fact in self.equivalences
                             for reference in (fact.left, fact.right)})
        if not references:
            return {}
        for inventory, point in references:
            if point not in self.known_points[inventory]:
                raise ValueError(f"equivalence references absent point {point} in inventory {inventory}")
        indexes = {reference: index for index, reference in enumerate(references)}
        pairs = [(indexes[(fact.left.inventory, fact.left.point)], indexes[(fact.right.inventory, fact.right.point)])
                 for fact in self.equivalences]
        adjacency = coo_array((np.ones(len(pairs)), tuple(zip(*pairs, strict=True))),
                              shape=(len(references), len(references)))
        _, components = connected_components(adjacency, directed=False)
        canonical: dict[int, tuple[str, str]] = {}
        for reference, component in zip(references, components, strict=True):
            canonical.setdefault(int(component), reference)
        return {reference: canonical[int(component)] for reference, component in zip(references, components, strict=True)}

    @cached_property
    def sources(self) -> StitchSources:
        return StitchSources(points=self.points, sources={identity: StitchSource(
            allocation=graph.allocation, feedback=graph.feedback)
            for identity, graph in self.graphs.items()})

    @cached_property
    def equivalence_graph(self) -> EquivalenceGraph | None:
        if not self.equivalences:
            return None
        edges = [edge.model_copy(update={"inventory": identity}) for identity, graph in self.graphs.items()
                 for edge in graph.edges]
        trails, cycles = beam_search(edges, self.sources, self.settings.width, self.settings.max_hops, frozenset())
        crossing = [trail for trail in trails if len({edge.inventory for edge in trail.edges}) > 1]
        circular = [trail for trail in cycles if len({edge.inventory for edge in trail.edges}) > 1]
        if not crossing and not circular:
            return None
        ranked = sorted((self.witnessed_chain(chain) for chain in ranked_chains(
            crossing, self.sources, [], self.settings.min_count_increase, {})), key=Chain.rank, reverse=True)
        cross_layer = [chain for chain in ranked if chain.crosses_layers and chain.terminal]
        kept = {chain.key: chain for chain in (*ranked[:self.settings.kept], *cross_layer[:CROSS_LAYER_KEPT])}
        return EquivalenceGraph(equivalences=tuple(fact.identity for fact in self.equivalences), edges=tuple(edges),
            chains=tuple(sorted(kept.values(), key=Chain.rank, reverse=True)),
            cycles=tuple(self.witnessed_chain(chain) for chain in ranked_chains(
                circular, self.sources, [], self.settings.min_count_increase, {})))

    @cached_property
    def chains(self) -> dict[PathIdentity, Chain]:
        found: dict[PathIdentity, Chain] = {}
        for identity, graph in self.graphs.items():
            for chain in (*graph.judged_stitching.top, *graph.judged_stitching.top_cross_layer):
                found.setdefault(PathIdentity.from_chain(chain, identity), chain)
        joined = self.equivalence_graph
        if joined is not None:
            for chain in joined.chains:
                found.setdefault(PathIdentity.from_chain(chain, ""), chain)
        return found

    def path_chain(self, path: PathIdentity) -> Chain:
        if path not in self.chains:
            raise ValueError("the path has no standing measured chain under these compute settings")
        return self.chains[path]

    def targets(self, chain: Chain) -> tuple[PathTarget, ...]:
        """Actual inventories where every source intervention and deviation has an explicit point mapping."""
        targets = []
        for identity, graph in self.graphs.items():
            known = self.known_points[identity]
            workload = merged_workload(chain.condition, graph.variants.scenarios).workload
            if any(merged_workload(chain.condition, self.graphs[hop.inventory].variants.scenarios).workload != workload
                   for hop in chain.hops if hop.inventory):
                continue
            hops = []
            for hop in chain.hops:
                if hop.inventory is None:
                    raise ValueError("a cross-inventory path requires the inventory of every hop")
                matched = []
                for point in (hop.cause.point, hop.effect.point):
                    canonical = self.points.get((hop.inventory, point), (hop.inventory, point))
                    matches = [candidate for candidate in known
                               if self.points.get((identity, candidate), (identity, candidate)) == canonical]
                    if len(matches) != 1:
                        break
                    mapped = matches[0]
                    if point_kind(point) in BOUNDARY_KINDS or point_kind(mapped) in BOUNDARY_KINDS:
                        source_grpc = point.split(":", 2)[2].partition(" ")[0] == GRPC_METHOD
                        target_grpc = mapped.split(":", 2)[2].partition(" ")[0] == GRPC_METHOD
                        if point_kind(point) != point_kind(mapped) or source_grpc != target_grpc:
                            break
                    matched.append(mapped)
                if len(matched) != 2:
                    break
                cause_point, effect_point = matched
                layer = point_layer(cause_point, graph.topology.upstream)
                cause = hop.cause.model_copy(update={"point": cause_point, "layer": layer,
                                                    "scoped": point_scoped(cause_point, layer, graph.kinds)})
                group = Group(workload=merged_workload(chain.condition, graph.variants.scenarios), faults=(cause,))
                rules = group.ruleset(group.labels(2)[0])
                if graph.kinds.violations(rules) or manifest_violations(rules, graph.inventory.manifests):
                    break
                manifest = point_manifests(graph.inventory.manifests).get(cause_point)
                if (manifest is not None and manifest.language == GO_LANGUAGE
                        and any(rule.kind == PointKind.CALL and rule.action.model_dump().get(ERROR) is not None
                                and rule.action.model_dump()[ERROR] not in manifest.errors for rule in rules.rules)):
                    break
                hops.append(hop.model_copy(update={"cause": cause,
                    "effect": hop.effect.model_copy(update={"point": effect_point}),
                    "effect_layer": point_layer(effect_point, graph.topology.upstream)}))
            if len(hops) == len(chain.hops):
                targets.append(PathTarget(inventory=identity, chain=chain.model_copy(
                    update={"hops": tuple(hops), "origin": chain.key})))
        return tuple(targets)

    def headroom(self, chain: Chain, target: PathTarget) -> Headroom:
        """Compare the original edges' measured levels with actual controls at an executable target."""
        graph = self.graphs[target.inventory]
        workload = merged_workload(chain.condition, graph.variants.scenarios)
        if workload.name not in graph.controls:
            return Headroom(chains=())
        return headroom([target.chain], list(self.target_edges(chain, target)), graph.variants.scenarios,
                        self.settings.min_count_increase, [graph.controls[workload.name]], graph.repetitions)

    def target_edges(self, chain: Chain, target: PathTarget) -> tuple[Edge, ...]:
        """Project measured edge endpoints onto their unique executable target, retaining original sightings."""
        edges = []
        for source_hop, target_hop in zip(chain.hops, target.chain.hops, strict=True):
            if source_hop.inventory is None:
                raise ValueError("a cross-inventory path requires the inventory of every hop")
            edge = next(edge for edge in self.graphs[source_hop.inventory].edges
                        if edge.cause == source_hop.cause and edge.effect == source_hop.effect)
            edges.append(edge.model_copy(update={"cause": target_hop.cause, "effect": target_hop.effect,
                                                 "effect_layer": target_hop.effect_layer}))
        return tuple(edges)

    @cached_property
    def witnesses(self) -> dict[str, Witnesses]:
        return {identity: Witnesses.of([record for record in graph.records if any(record.injected)],
                                      self.settings.min_count_increase) for identity, graph in self.graphs.items()}

    def witnessed_chain(self, chain: Chain) -> Chain:
        """Judge visibility in each actual target's native EDGE records, without pooling contexts."""
        witnesses: list[ChainWitness] = []
        comparable = []
        shared_scenario = False
        for target in self.targets(chain):
            graph = self.graphs[target.inventory]
            actual = {(edge.cause.key, edge.effect.key): edge for edge in graph.edges}
            projected = self.target_edges(chain, target)
            native = tuple(edge.model_copy(update={"held": actual[(edge.cause.key, edge.effect.key)].held
                if (edge.cause.key, edge.effect.key) in actual else ()}) for edge in projected)
            witness = self.witnesses[target.inventory].chain(native).model_copy(update={"inventory": target.inventory})
            witnesses.append(witness)
            if self.witnesses[target.inventory].shown.get(native[0].cause.key):
                comparable.append(witness)
            shared_scenario |= bool(frozenset.intersection(*(edge.held_in for edge in native)))
        end_to_end = tuple(sorted({scenario for witness in comparable for scenario in witness.end_to_end}))
        undetermined = {scenario for witness in comparable for scenario in witness.undetermined}
        if not comparable:
            first = chain.hops[0]
            if first.inventory is None:
                raise ValueError("a cross-inventory path requires the inventory of every hop")
            undetermined.update(scenario for scenario, _ in self.witnesses[first.inventory].shown.get(first.cause.key, ()))
        contradicted = set.intersection(*(set(witness.contradicted) for witness in comparable)) if comparable else set()
        return chain.model_copy(update={"witnesses": tuple(witnesses), "end_to_end": end_to_end,
            "undetermined": tuple(sorted(undetermined - set(end_to_end))),
            "contradicted": tuple(sorted(contradicted)) if not end_to_end else (),
            "several_scenarios": not (shared_scenario or end_to_end)})

    @cached_property
    def natural(self) -> tuple[NaturalJudgement, ...]:
        requested = {(run.natural.path, run.natural.inventory) for run in self.facts.standing_runs()
                     if run.natural is not None and run.natural.inventory is not None
                     and ({deviation.inventory for deviation in run.natural.path.deviations}
                          != {run.natural.inventory})}
        if not requested:
            return ()
        judgements: list[NaturalJudgement] = []
        for identity, inventory in sorted(requested, key=lambda request: repr(request)):
            if identity not in self.chains:
                continue
            chain = self.chains[identity]
            source = identity.deviations[0].inventory
            scoped = chain.model_copy(update={"hops": tuple(hop.model_copy(
                update={"inventory": hop.inventory or source}) for hop in chain.hops)})
            for target in self.targets(scoped):
                if target.inventory != inventory:
                    continue
                graph = self.graphs[target.inventory]
                found = natural_comparisons(self.facts, {identity: target.chain}, graph.inventory,
                    self.settings.alpha, self.settings.min_mean_increase, self.settings.min_count_increase)
                judgements.extend(judgement.model_copy(update={"hops": tuple(hop.model_copy(
                    update={"effect": chain.hops[index].effect}) for index, hop in enumerate(judgement.hops))})
                    for judgement in found)
        return tuple(sorted(judgements, key=lambda judgement: max(
            fact.sequence for fact in self.facts.standing_runs() if fact.identity in judgement.runs)))


def compute_graph(facts: Facts, settings: ComputeSettings) -> PropagationGraphs:
    measured = EquivalentGraphs(facts, settings)
    return PropagationGraphs(settings=settings, through=facts.facts[-1].sequence if facts.facts else 0,
        inventories=tuple(InventoryGraph(inventory=identity, graph=graph.graph())
                          for identity, graph in measured.graphs.items()),
        equivalence=measured.equivalence_graph, natural=measured.natural)


def print_graph() -> None:
    parser = argparse.ArgumentParser(description="Compute every standing inventory's graph from its recorded evidence.")
    parser.add_argument("facts", type=Path)
    parser.add_argument("settings", type=Path)
    arguments = parser.parse_args()
    print(compute_graph(read_facts(arguments.facts), ComputeSettings.model_validate_json(
        arguments.settings.read_bytes())).model_dump_json())


def print_graph_schema() -> None:
    print(json.dumps(PropagationGraphs.model_json_schema(), indent=2))
