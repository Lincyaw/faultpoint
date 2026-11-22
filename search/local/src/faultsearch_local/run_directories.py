from collections import Counter

from faultpoint.rules import RuleSet
from faultsearch.allocation import Allocation, Phase, Strategy
from faultsearch.catalog import Catalog, read_manifests
from faultsearch.chains import Stitching
from faultsearch.counterfactual import DEFAULT_SEED, ControlRecord, Load, NamedWorkload, Scenarios, TreatmentRecord
from faultsearch.edges import EdgeSet, EffectMap
from faultsearch.evidence import MappingFeedback
from faultsearch.facts import (CONTROL_GROUP, Fact, Facts, LoadVariants, PathRequest, PointInventory, Purpose,
                               SystemTopology)
from faultsearch.graph import PropagationGraph
from faultsearch.validation import VALIDATION_PREFIX, Headroom, Selection, Validation, Validations
from pydantic import BaseModel

from faultsearch_local.executor import RunSettings
from faultsearch_local.facts_file import RULES_FILE, RunOrigin
from faultsearch_local.store import (CATALOG, CONTROLS, EFFECTS_INPUT, HEADROOM, INPUTS, MAPPING_FEEDBACK, REPETITIONS,
                                     RUN_SETTINGS, SCENARIOS_INPUT, TREATMENTS, VALIDATIONS, Store, allocation_file,
                                     chains_file, edges_file)
from faultsearch_local.systems import STATUSES_FILE, System


class Imported(BaseModel):
    """An experiment directory's facts, and the repetition directories they leave out because no record of the
    experiment refers to them."""

    facts: Facts
    unreferenced: tuple[str, ...]
    """Those that ran to their end."""
    unfinished: tuple[str, ...]
    """Those without statuses, which never ran to their end."""


class RunImport:
    """The conversion of one experiment directory's repetitions into search runs, numbered in the order they are
    taken."""

    def __init__(self, store: Store, system: System, settings: RunSettings) -> None:
        self.store = store
        self.origin = RunOrigin(store, system.name, settings.commit)
        self.facts: list[Fact] = []
        self.taken: set[str] = set()

    def run(self, label: str, workload: NamedWorkload, group: str, index: int, purpose: Purpose,
            phases: tuple[Phase, ...], requests: tuple[PathRequest, ...]) -> None:
        """One repetition directory as a search run, unless taken before."""
        if label not in self.taken:
            self.taken.add(label)
            self.facts.append(self.origin.search_run(label, len(self.facts) + 1, workload, group, index, purpose,
                                                     phases, requests))

    def controls(self, control: ControlRecord, purpose: Purpose) -> None:
        for index, label in enumerate(control.labels):
            self.run(label, control.workload, CONTROL_GROUP, index, purpose, (), ())

    def treatments(self, record: TreatmentRecord, workload: NamedWorkload, purpose: Purpose,
                   phases: dict[str, Phase], requests: tuple[PathRequest, ...]) -> None:
        """The repetitions of a treatment record, with the phase of every fault their rules inject, by the id of the
        fault's own rule."""
        for index, label in enumerate(record.labels):
            rules = RuleSet.model_validate_json((self.store.repetition(label) / RULES_FILE).read_bytes()).rules
            self.run(label, workload, label.split(".")[-2], index, purpose,
                     tuple(phases[rule.id] for rule in rules if rule.id in phases), requests)


def experiment_facts(store: Store, system: System) -> Imported:
    """An experiment directory written before facts, as facts: the system's topology and load variants, the control
    runs of every load variant and the point inventory they complete, the runs of every assignment of the phased
    allocation in its order, the controls of the merged workloads and the runs of the validations. Only the
    repetitions a record of the experiment refers to are taken."""
    settings = store.load(RunSettings, RUN_SETTINGS)
    scenarios = store.load(Scenarios, INPUTS, SCENARIOS_INPUT)
    effects = store.load(EffectMap, INPUTS, EFFECTS_INPUT)
    taking = RunImport(store, system, settings)
    taking.facts.append(SystemTopology(sequence=1, system=system.name, upstream=system.upstream,
                                       entry_service=system.entry_service, terminal_outcomes=effects.terminal_outcomes,
                                       ports=system.ports, targets=system.targets))
    taking.facts.append(LoadVariants(sequence=2, system=system.name, scenarios=scenarios))
    controls = {path.stem: store.load(ControlRecord, CONTROLS, path.name)
                for path in sorted(store.path(CONTROLS).glob("*.json"))}
    variants = [scenario.name for scenario in scenarios.scenarios]
    for name in variants:
        taking.controls(controls[name], Purpose.EDGE)
    taking.facts.append(PointInventory(sequence=len(taking.facts) + 1, system=system.name, revision=None,
                                       sdk_build=settings.commit, deployment=settings.instrumentation,
                                       controls=tuple(label for name in variants for label in controls[name].labels),
                                       manifests=read_manifests(system.manifests), configured=system.configured))
    allocation = store.load(Allocation, allocation_file(Strategy.PHASED))
    phases: dict[str, dict[str, Phase]] = {name: {} for name in variants}
    for assignment in allocation.assignments:
        phases[assignment.scenario][assignment.fault.digest] = assignment.phase
    for assignment in allocation.assignments:
        record = store.load(TreatmentRecord, TREATMENTS, assignment.scenario, f"{assignment.fault.digest}.json")
        taking.treatments(record, NamedWorkload(name=assignment.scenario, workload=scenarios.workload(
            assignment.scenario)), Purpose.EDGE, phases[assignment.scenario], ())
    for name, control in controls.items():
        if name.startswith(VALIDATION_PREFIX):
            taking.controls(control, Purpose.PATH)
    validations = store.load(Validations, VALIDATIONS).validations if store.has(VALIDATIONS) else ()
    requests: dict[tuple[str, ...], list[PathRequest]] = {}
    for validation in validations:
        if validation.selection != Selection.ADJUDICATED:
            requests.setdefault(validation.record.labels, []).append(
                PathRequest(chain=validation.chain.key, selection=validation.selection))
    for validation in validations:
        taking.treatments(validation.record, validation.workload, Purpose.PATH, {},
                          tuple(requests.get(validation.record.labels, ())))
    present = sorted(path.name for path in store.path(REPETITIONS).iterdir())
    left = [label for label in present if label not in taking.taken]
    return Imported(facts=Facts(facts=tuple(taking.facts)),
                    unreferenced=tuple(label for label in left if (store.repetition(label) / STATUSES_FILE).exists()),
                    unfinished=tuple(label for label in left if not (store.repetition(label) / STATUSES_FILE).exists()))


class Difference(BaseModel):
    """How far a computed record is from the recorded one: the fields that differ, and for those that sum floats the
    largest absolute and relative difference."""

    fields: tuple[str, ...]
    absolute: float
    relative: float


def float_values(record: TreatmentRecord) -> dict[tuple[str, ...], float]:
    values: dict[tuple[str, ...], float] = {("elapsed", key): value for key, value in record.elapsed.items()}
    values |= {("rates", key): value for key, value in record.rates.items()}
    values |= {("boundary", point, outcome, measure): getattr(load, measure)
               for point, outcomes in record.boundary.items() for outcome, load in outcomes.items()
               for measure in Load.model_fields}
    return values


def record_difference(computed: TreatmentRecord, recorded: TreatmentRecord) -> Difference:
    """The fields two records of one fault and workload differ in, a record from before seeds were kept standing for
    the default seed in every repetition; float fields with the same keys are measured, those whose keys differ count
    as differing fields with no measure."""
    seeded = recorded.model_copy(update={"seeds": recorded.seeds or tuple(DEFAULT_SEED for _ in recorded.labels)})
    fields = tuple(name for name in TreatmentRecord.model_fields if getattr(computed, name) != getattr(seeded, name))
    left, right = float_values(computed), float_values(recorded)
    gaps = [(abs(left[key] - right[key]), abs(left[key] - right[key]) / max(abs(right[key]), 1e-300))
            for key in left.keys() & right.keys()]
    return Difference(fields=fields, absolute=max((gap for gap, _ in gaps), default=0.0),
                      relative=max((gap for _, gap in gaps), default=0.0))


def validation_key(validation: Validation) -> tuple[str, str, str, bool, tuple[bool, ...]]:
    return (validation.chain.key, validation.workload.name, str(validation.selection), validation.confirmed,
            tuple(hop.confirmed for hop in validation.hops))


def graph_differences(graph: PropagationGraph, store: Store) -> list[str]:
    """Every comparison of a computed graph with an experiment directory's records, one line each."""
    lines = []

    def compared(name: str, same: bool, detail: str = "") -> None:
        lines.append(f"{'same' if same else 'DIFFERENT'}: {name}{f' ({detail})' if detail else ''}")

    compared("catalog", graph.catalog == store.load(Catalog, CATALOG))
    controls = {control.workload.name: control for control in graph.controls}
    recorded_controls = {path.stem: store.load(ControlRecord, CONTROLS, path.name)
                         for path in sorted(store.path(CONTROLS).glob("*.json"))}
    compared("control records", controls == recorded_controls, f"{len(controls)} computed, {len(recorded_controls)} recorded")
    for name, records in (("treatment records", graph.records), ("path records", graph.path_records)):
        differences = [record_difference(record, store.load(TreatmentRecord, TREATMENTS, record.workload,
                                                            f"{record.fault.digest}.json")) for record in records]
        differing = [difference for difference in differences if difference.fields]
        fields = Counter(field for difference in differing for field in difference.fields)
        compared(name, not differing, f"{len(records)} computed, {len(differing)} differ, in fields {dict(fields)}; "
                                      f"largest float difference {max(d.absolute for d in differences):.3g} absolute, "
                                      f"{max(d.relative for d in differences):.3g} relative")
    allocation = store.load(Allocation, allocation_file(Strategy.PHASED))
    compared("allocation", graph.allocation == allocation, f"{len(graph.allocation.assignments)} assignments, "
                                                           f"{len(graph.allocation.clusters)} clusters")
    edges = store.load(EdgeSet, edges_file(Strategy.PHASED)).edges
    compared("edges with their counterparts and mismatched counterparts", graph.edges == edges,
             f"{len(graph.edges)} computed, {len(edges)} recorded")
    stitching = store.load(Stitching, chains_file(Strategy.PHASED))
    compared("chains, keys and order", graph.stitching.keys == stitching.keys,
             f"{graph.stitching.chains} computed, {stitching.chains} recorded")
    compared("stitching, whole", graph.stitching == stitching)
    compared("headroom", graph.headroom == store.load(Headroom, HEADROOM), f"{len(graph.headroom.chains)} chains")
    recorded = store.load(Validations, VALIDATIONS).validations
    compared("path judgements, as a multiset", Counter(map(validation_key, graph.validations.validations))
             == Counter(map(validation_key, recorded)),
             f"{len(graph.validations.validations)} computed, {len(recorded)} recorded")
    feedback = store.load(MappingFeedback, MAPPING_FEEDBACK)
    compared("judgement feedback, as a set", set(graph.feedback.checks) == set(feedback.checks),
             f"{len(graph.feedback.checks)} computed, {len(feedback.checks)} recorded")
    judged = graph.judged_stitching
    lines.append(f"stitched again with the judgement: {judged.chains} chains, {len(judged.refuted_mappings)} refuted "
                 f"steps, {sum(chain.stitched_only for chain in judged.top_cross_layer)} stitched-only chains across "
                 f"layers to the user")
    return lines
