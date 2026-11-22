from collections import Counter

from faultsearch.allocation import Allocation, Strategy
from faultsearch.catalog import Catalog
from faultsearch.chains import Stitching
from faultsearch.counterfactual import DEFAULT_SEED, ControlRecord, Load, TreatmentRecord
from faultsearch.edges import EdgeSet
from faultsearch.evidence import MappingFeedback
from faultsearch.graph import PropagationGraph
from faultsearch.validation import Headroom, Validation, Validations
from pydantic import BaseModel

from faultsearch_local.store import (CATALOG, CONTROLS, HEADROOM, MAPPING_FEEDBACK, TREATMENTS, VALIDATIONS, Store,
                                     allocation_file, chains_file, edges_file)

FLOAT_FIELDS: tuple[str, ...] = ("elapsed", "rates", "boundary")
"""The record fields that sum floats over repetitions, whose last bits depend on the order of the sums."""


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
