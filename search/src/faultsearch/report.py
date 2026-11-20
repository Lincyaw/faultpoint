from collections import Counter, defaultdict
from typing import Final

from faultpoint.tools.analysis import Metric
from pydantic import BaseModel

from faultsearch.allocation import Allocation, Strategy
from faultsearch.catalog import FROZEN, Catalog, Exclusion
from faultsearch.chains import Stitching
from faultsearch.edges import Counterpart, Edge, EdgeSet, EffectKey, EffectMap
from faultsearch.fca import ControlRecord, Leak, RunSettings, TreatmentRecord, treatment_record
from faultsearch.store import (CATALOG, CONTROLS, EFFECTS_INPUT, INPUTS, LEAKS, REPETITIONS, RUN_SETTINGS,
                               TREATMENTS, VALIDATIONS, Store, allocation_file, chains_file, edges_file)
from faultsearch.validation import VALIDATION_PREFIX, Selection, Validations

EXAMPLES_PER_CONDITION: Final = 2
QUERY_SEPARATOR: Final = " => "


class StrategySummary(BaseModel):
    model_config = FROZEN

    strategy: Strategy
    injections: int
    exercised: int
    phases: dict[str, int]
    cluster_sizes: tuple[int, ...]
    edges: int
    conditional: int
    """Edges with a tested scenario where they did not hold."""
    tested_once: int
    """Edges whose fault was tested in one scenario only, so that nothing tells whether they are conditional."""
    counterparts: dict[str, int]
    chains: int
    stitched_only: int
    single_scenario: int
    cycles: int


class ValidationSummary(BaseModel):
    model_config = FROZEN

    chain: str
    selection: Selection
    workload: str
    stitched_only: bool
    exercised: bool
    hops: tuple[bool, ...]
    confirmed: bool
    random_has_edges: bool
    random_has_chain: bool


class EdgeComparison(BaseModel):
    """The edges 3PA and random allocation found with the same budget."""

    model_config = FROZEN

    shared: int
    only_three_phase: int
    only_random: int
    conditional_only_three_phase: int
    conditional_only_random: int
    terminal_chains: dict[str, int]
    """Stitched-only chains ending in a failure the user sees, by strategy."""


class SingleScenarioView(BaseModel):
    """What single scenarios show end to end without stitching: (first fault, user-visible failure) pairs."""

    model_config = FROZEN

    end_to_end: dict[str, int]
    union: int
    stitched: int
    """Such pairs that 3PA's stitched-only chains reach."""
    beyond_single: int
    """Of those, the pairs no single injection of the first fault showed in any scenario it was tested in."""


class EdgeLookup(BaseModel):
    model_config = FROZEN

    query: str
    found: dict[str, tuple[Edge, ...]]


class Summary(BaseModel):
    model_config = FROZEN

    commit: str
    settings: RunSettings
    faults: int
    points: int
    excluded: tuple[Exclusion, ...]
    repetitions: dict[str, int]
    strategies: tuple[StrategySummary, ...]
    conditional_examples: tuple[Edge, ...]
    validations: tuple[ValidationSummary, ...]
    edges: EdgeComparison
    single: SingleScenarioView
    lookups: tuple[EdgeLookup, ...]


def repetition_counts(store: Store, repetitions: int) -> dict[str, int]:
    """The repetitions the records rest on, and those no record uses, which an interrupted run left."""
    controls = {label for path in store.path(CONTROLS).glob("*.json")
                for label in store.load(ControlRecord, CONTROLS, path.name).labels}
    treatments = {label for path in store.path(TREATMENTS).glob("*/*.json")
                  for label in store.load(TreatmentRecord, TREATMENTS, path.parent.name, path.name).labels}
    leaked = {label for path in store.path(LEAKS).glob("*/*.json")
              for label in store.load(Leak, LEAKS, path.parent.name, path.name).group.labels(repetitions)}
    run = {path.parent.name for path in store.path(REPETITIONS).glob("*/statuses.json")}
    validation = {label for label in run if label.startswith(VALIDATION_PREFIX)}
    return {"scenario controls": len(controls - validation), "exploration treatments": len(treatments - validation),
            "packed repetitions that leaked": len(leaked), "validation controls": len(controls & validation),
            "validation treatments": len(treatments & validation), "unused": len(run - controls - treatments - leaked)}


def strategy_summary(allocation: Allocation, records: list[TreatmentRecord], edges: EdgeSet,
                     stitching: Stitching) -> StrategySummary:
    tested = Counter(record.fault.key for record in records if record.exercised)
    return StrategySummary(
        strategy=allocation.strategy, injections=len(records), exercised=sum(tested.values()),
        phases=dict(Counter(assignment.phase.value for assignment in allocation.assignments)),
        cluster_sizes=tuple(sorted((len(cluster.members) for cluster in allocation.clusters), reverse=True)),
        edges=len(edges.edges), conditional=sum(bool(edge.not_held) for edge in edges.edges),
        tested_once=sum(tested[edge.cause.key] == 1 for edge in edges.edges),
        counterparts=dict(Counter(edge.counterpart.value for edge in edges.edges)), chains=stitching.chains,
        stitched_only=stitching.stitched_only, single_scenario=stitching.single_scenario,
        cycles=len(stitching.cycles))


def edge_comparison(edges: dict[Strategy, EdgeSet], stitchings: dict[Strategy, Stitching]) -> EdgeComparison:
    keys = {strategy: {edge.key for edge in edge_set.edges} for strategy, edge_set in edges.items()}
    conditional = {strategy: {edge.key for edge in edge_set.edges if edge.not_held}
                   for strategy, edge_set in edges.items()}
    three_phase, uniform = Strategy.THREE_PHASE, Strategy.RANDOM
    return EdgeComparison(
        shared=len(keys[three_phase] & keys[uniform]), only_three_phase=len(keys[three_phase] - keys[uniform]),
        only_random=len(keys[uniform] - keys[three_phase]),
        conditional_only_three_phase=len(conditional[three_phase] - keys[uniform]),
        conditional_only_random=len(conditional[uniform] - keys[three_phase]),
        terminal_chains={strategy: stitching.terminal_stitched_only for strategy, stitching in stitchings.items()})


def single_scenario_view(records: list[TreatmentRecord], stitching: Stitching,
                         effects: EffectMap) -> SingleScenarioView:
    shown: dict[str, set[tuple[str, str]]] = {}
    for record in records:
        shown.setdefault(record.workload, set()).update(
            (record.fault.key, key.key) for key in map(EffectKey.of, record.effects) if effects.terminal(key))
    union = set().union(*shown.values())
    stitched = set(stitching.stitched_terminal_pairs)
    return SingleScenarioView(end_to_end={name: len(pairs) for name, pairs in shown.items()}, union=len(union),
                              stitched=len(stitched), beyond_single=len(stitched - union))


def validation_summaries(validations: Validations, edges: EdgeSet, stitching: Stitching) -> list[ValidationSummary]:
    keys = {edge.key for edge in edges.edges}
    chains = set(stitching.keys)
    return [ValidationSummary(
        chain=validation.chain.key, selection=validation.selection, workload=validation.workload.name,
        stitched_only=validation.chain.stitched_only,
        exercised=validation.record.exercised, hops=tuple(hop.confirmed for hop in validation.hops),
        confirmed=validation.confirmed,
        random_has_edges=all(f"[{hop.cause.key}] {hop.effect.key}" in keys for hop in validation.chain.hops),
        random_has_chain=validation.chain.key in chains) for validation in validations.validations]


def conditional_examples(edges: EdgeSet) -> tuple[Edge, ...]:
    """Conditional edges that can continue a chain or end one, at most two per learned condition: those ending at
    the user first, then counts before means."""
    useful = sorted((edge for edge in edges.edges if edge.not_held
                     and (edge.terminal or edge.counterpart == Counterpart.INJECTABLE)),
                    key=lambda edge: (not edge.terminal, edge.effect.metric != Metric.COUNT, -len(edge.held), edge.key))
    by_condition: dict[str, list[Edge]] = defaultdict(list)
    for edge in useful:
        by_condition[condition_text(edge)].append(edge)
    return tuple(edge for examples in by_condition.values() for edge in examples[:EXAMPLES_PER_CONDITION])


def summarise(store: Store, queries: list[str]) -> Summary:
    catalog = store.load(Catalog, CATALOG)
    settings = store.load(RunSettings, RUN_SETTINGS)
    allocations = {strategy: store.load(Allocation, allocation_file(strategy)) for strategy in Strategy}
    records = {strategy: [treatment_record(store, assignment.fault, assignment.scenario)
                          for assignment in allocation.assignments] for strategy, allocation in allocations.items()}
    edges = {strategy: store.load(EdgeSet, edges_file(strategy)) for strategy in Strategy}
    stitchings = {strategy: store.load(Stitching, chains_file(strategy)) for strategy in Strategy}
    return Summary(
        commit=settings.commit, settings=settings, faults=len(catalog.faults), points=len(catalog.uses),
        excluded=catalog.excluded, repetitions=repetition_counts(store, settings.repetitions),
        strategies=tuple(strategy_summary(allocations[strategy], records[strategy], edges[strategy],
                                          stitchings[strategy]) for strategy in Strategy),
        conditional_examples=conditional_examples(edges[Strategy.THREE_PHASE]),
        validations=tuple(validation_summaries(store.load(Validations, VALIDATIONS), edges[Strategy.RANDOM],
                                               stitchings[Strategy.RANDOM])),
        edges=edge_comparison(edges, stitchings),
        single=single_scenario_view(records[Strategy.THREE_PHASE], stitchings[Strategy.THREE_PHASE],
                                    store.load(EffectMap, INPUTS, EFFECTS_INPUT)),
        lookups=tuple(EdgeLookup(query=query, found={
            strategy: tuple(edge for edge in edge_set.edges
                            if f"[{query.split(QUERY_SEPARATOR)[0]}] {query.split(QUERY_SEPARATOR)[1]}" == edge.key)
            for strategy, edge_set in edges.items()}) for query in queries))


def condition_text(edge: Edge) -> str:
    return " or ".join(", ".join(f"{name}={value}" for name, value in condition.items()) or "baseline"
                       for condition in edge.conditions)


def render(summary: Summary) -> str:
    lines = [f"SDK {summary.commit}; {summary.faults} faults over {summary.points} points, "
             f"{len(summary.excluded)} points excluded",
             *(f"  excluded {exclusion.point}: {exclusion.reason}" for exclusion in summary.excluded),
             "repetitions: " + ", ".join(f"{name} {count}" for name, count in summary.repetitions.items())]
    for strategy in summary.strategies:
        lines += [f"{strategy.strategy}: {strategy.injections} injections ({strategy.exercised} exercised) "
                  f"{strategy.phases}; clusters {strategy.cluster_sizes}",
                  f"  edges {strategy.edges}: {strategy.conditional} conditional, "
                  f"{strategy.edges - strategy.conditional} unconditional ({strategy.tested_once} of a fault tested "
                  f"in one scenario); counterparts {strategy.counterparts}",
                  f"  chains {strategy.chains}: {strategy.stitched_only} stitched only, {strategy.single_scenario} "
                  f"shown end to end by one scenario; cycles {strategy.cycles}"]
    lines += ["conditional edges:", *(f"  {edge.key} | held {sorted(edge.held_in)} not {list(edge.not_held)} | "
                                       f"condition {condition_text(edge)}" for edge in summary.conditional_examples)]
    lines += ["validations:", *(f"  {'confirmed' if item.confirmed else 'refuted'} {item.selection} "
                                f"{'stitched-only' if item.stitched_only else 'single-scenario'} in {item.workload} "
                                f"hops {''.join('+' if hop else '-' for hop in item.hops)} random edges "
                                f"{item.random_has_edges} chain {item.random_has_chain}\n    {item.chain}"
                                for item in summary.validations)]
    lines += [f"edges 3pa vs random: {summary.edges.model_dump()}", f"single scenarios: {summary.single.model_dump()}"]
    lines += [f"lookup {lookup.query}: " + "; ".join(
        f"{strategy} " + (" ".join(f"held {sorted(edge.held_in)} not {list(edge.not_held)} condition "
                                   f"{condition_text(edge)}" for edge in found) or "absent")
        for strategy, found in lookup.found.items()) for lookup in summary.lookups]
    return "\n".join(lines)
