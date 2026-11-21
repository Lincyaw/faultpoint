from collections import Counter, defaultdict
from typing import Final

from faultpoint.tools.analysis import Metric
from pydantic import BaseModel

from faultsearch.allocation import Allocation, Strategy
from faultsearch.catalog import FROZEN, Catalog, Exclusion, Layer
from faultsearch.chains import LAYER_PATH_SEPARATOR, Chain, Stitching
from faultsearch.counterfactual import ControlRecord, EffectKey, Leak, RunSettings, TreatmentRecord, treatment_record
from faultsearch.edges import Edge, EdgeSet, EffectMap
from faultsearch.store import (CATALOG, CONTROLS, EFFECTS_INPUT, INPUTS, LEAKS, MAPPING_FEEDBACK, REPETITIONS,
                               RUN_SETTINGS, TREATMENTS, VALIDATIONS, Store, allocation_file, chains_file, edges_file)
from faultsearch.validation import VALIDATION_PREFIX, MappingFeedback, Selection, Validations

EXAMPLES_PER_CONDITION: Final = 2
CROSS_LAYER_SHOWN: Final = 15
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
    edge_layers: dict[str, int]
    """Edges by the layer of their fault and of their effect."""
    chains: int
    stitched_only: int
    single_scenario: int
    cycles: int
    layer_paths: dict[str, int]
    stitched_layer_paths: dict[str, int]


class ValidationSummary(BaseModel):
    model_config = FROZEN

    chain: str
    hops_text: tuple[str, ...]
    """Every hop with the layers of its fault and effect, and what a fault no rule can scope acted on."""
    layer_path: str
    selection: Selection
    workload: str
    stitched_only: bool
    exercised: bool
    hops: tuple[bool, ...]
    confirmed: bool
    random_has_edges: bool | None
    """Whether the random allocation found every edge of the chain; absent when it did not run."""
    random_has_chain: bool | None


class LayerEffect(BaseModel):
    """An effect at a layer below the business code, which the business points alone would never show."""

    model_config = FROZEN

    effect: str
    layer: Layer
    causes: dict[str, int]
    """The faults that caused it, counted by their layer."""


class EdgeComparison(BaseModel):
    """The edges the phased and the random allocation found with the same budget."""

    model_config = FROZEN

    shared: int
    only_phased: int
    only_random: int
    conditional_only_phased: int
    conditional_only_random: int
    terminal_chains: dict[str, int]
    """Stitched-only chains ending in a failure the user sees, by strategy."""


class SingleScenarioView(BaseModel):
    """What single scenarios show end to end without stitching: (first fault, user-visible failure) pairs."""

    model_config = FROZEN

    end_to_end: dict[str, int]
    union: int
    stitched: int
    """Such pairs that the phased allocation's stitched-only chains reach."""
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
    cross_layer_chains: tuple[Chain, ...]
    layer_effects: tuple[LayerEffect, ...]
    validations: tuple[ValidationSummary, ...]
    min_count_increase: float
    feedback: dict[str, int]
    """Validated hops checking a correspondence of the effect map, confirmed and refuted, and the steps stitching no
    longer took."""
    edges: EdgeComparison | None
    """Absent when the random allocation did not run."""
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
        counterparts=dict(Counter(edge.counterpart.value for edge in edges.edges)),
        edge_layers=dict(Counter(f"{edge.cause.layer}{LAYER_PATH_SEPARATOR}{edge.effect_layer}" for edge in edges.edges)),
        chains=stitching.chains, stitched_only=stitching.stitched_only, single_scenario=stitching.single_scenario,
        cycles=len(stitching.cycles), layer_paths=stitching.layer_paths,
        stitched_layer_paths=stitching.stitched_layer_paths)


def layer_effects(edges: EdgeSet) -> tuple[LayerEffect, ...]:
    """The effects at the library and upstream layers, those with the most causes first."""
    causes: dict[tuple[str, Layer], Counter[str]] = defaultdict(Counter)
    for edge in edges.edges:
        if edge.effect_layer in (Layer.LIBRARY, Layer.UPSTREAM):
            causes[(edge.effect.key, edge.effect_layer)][edge.cause.layer] += 1
    return tuple(LayerEffect(effect=effect, layer=layer, causes=dict(counted))
                 for (effect, layer), counted in sorted(causes.items(), key=lambda item: -item[1].total()))


def edge_comparison(edges: dict[Strategy, EdgeSet], stitchings: dict[Strategy, Stitching]) -> EdgeComparison:
    keys = {strategy: {edge.key for edge in edge_set.edges} for strategy, edge_set in edges.items()}
    conditional = {strategy: {edge.key for edge in edge_set.edges if edge.not_held}
                   for strategy, edge_set in edges.items()}
    phased, uniform = Strategy.PHASED, Strategy.RANDOM
    return EdgeComparison(
        shared=len(keys[phased] & keys[uniform]), only_phased=len(keys[phased] - keys[uniform]),
        only_random=len(keys[uniform] - keys[phased]),
        conditional_only_phased=len(conditional[phased] - keys[uniform]),
        conditional_only_random=len(conditional[uniform] - keys[phased]),
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


def validation_summaries(validations: Validations, random_edges: EdgeSet | None,
                         random_stitching: Stitching | None) -> list[ValidationSummary]:
    keys = None if random_edges is None else {edge.key for edge in random_edges.edges}
    chains = None if random_stitching is None else set(random_stitching.keys)
    return [ValidationSummary(
        chain=validation.chain.key, hops_text=tuple(hop.text for hop in validation.chain.hops),
        layer_path=validation.chain.layer_path, selection=validation.selection,
        workload=validation.workload.name, stitched_only=validation.chain.stitched_only,
        exercised=validation.record.exercised, hops=tuple(hop.confirmed for hop in validation.hops),
        confirmed=validation.confirmed,
        random_has_edges=None if keys is None else all(f"[{hop.cause.key}] {hop.effect.key}" in keys
                                                       for hop in validation.chain.hops),
        random_has_chain=None if chains is None else validation.chain.key in chains)
        for validation in validations.validations]


def conditional_examples(edges: EdgeSet) -> tuple[Edge, ...]:
    """Conditional edges that can continue a chain or end one, at most two per learned condition: those ending at
    the user first, then counts before means."""
    useful = sorted((edge for edge in edges.edges if edge.not_held and (edge.terminal or edge.counterparts)),
                    key=lambda edge: (not edge.terminal, edge.effect.metric != Metric.COUNT, -len(edge.held), edge.key))
    by_condition: dict[str, list[Edge]] = defaultdict(list)
    for edge in useful:
        by_condition[condition_text(edge)].append(edge)
    return tuple(edge for examples in by_condition.values() for edge in examples[:EXAMPLES_PER_CONDITION])


def feedback_counts(feedback: MappingFeedback, stitching: Stitching) -> dict[str, int]:
    return {"checks": len(feedback.checks), "confirmed": sum(check.confirmed for check in feedback.checks),
            "refuted": sum(not check.confirmed for check in feedback.checks),
            "steps left out of the stitching": len(stitching.refuted_mappings)}


def summarise(store: Store, queries: list[str]) -> Summary:
    """The summary of the strategies that ran, the phased allocation always among them."""
    catalog = store.load(Catalog, CATALOG)
    settings = store.load(RunSettings, RUN_SETTINGS)
    strategies = [strategy for strategy in Strategy if store.has(allocation_file(strategy))]
    allocations = {strategy: store.load(Allocation, allocation_file(strategy)) for strategy in strategies}
    records = {strategy: [treatment_record(store, assignment.fault, assignment.scenario)
                          for assignment in allocation.assignments] for strategy, allocation in allocations.items()}
    edges = {strategy: store.load(EdgeSet, edges_file(strategy)) for strategy in strategies}
    stitchings = {strategy: store.load(Stitching, chains_file(strategy)) for strategy in strategies}
    return Summary(
        commit=settings.commit, settings=settings, faults=len(catalog.faults), points=len(catalog.uses),
        excluded=catalog.excluded, repetitions=repetition_counts(store, settings.repetitions),
        strategies=tuple(strategy_summary(allocations[strategy], records[strategy], edges[strategy],
                                          stitchings[strategy]) for strategy in strategies),
        conditional_examples=conditional_examples(edges[Strategy.PHASED]),
        cross_layer_chains=stitchings[Strategy.PHASED].top_cross_layer[:CROSS_LAYER_SHOWN],
        layer_effects=layer_effects(edges[Strategy.PHASED]),
        validations=tuple(validation_summaries(store.load(Validations, VALIDATIONS), edges.get(Strategy.RANDOM),
                                               stitchings.get(Strategy.RANDOM))),
        min_count_increase=stitchings[Strategy.PHASED].min_count_increase,
        feedback=feedback_counts(store.load(MappingFeedback, MAPPING_FEEDBACK) if store.has(MAPPING_FEEDBACK)
                                 else MappingFeedback(checks=()), stitchings[Strategy.PHASED]),
        edges=edge_comparison(edges, stitchings) if Strategy.RANDOM in strategies else None,
        single=single_scenario_view(records[Strategy.PHASED], stitchings[Strategy.PHASED],
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
                  f"  edges by layer {strategy.edge_layers}",
                  f"  chains {strategy.chains}: {strategy.stitched_only} stitched only, {strategy.single_scenario} "
                  f"shown end to end by one scenario; cycles {strategy.cycles}",
                  f"  stitched-only chains by layer path {strategy.stitched_layer_paths}"]
    lines += ["conditional edges:", *(f"  {edge.key} | held {sorted(edge.held_in)} not {list(edge.not_held)} | "
                                       f"condition {condition_text(edge)}" for edge in summary.conditional_examples)]
    lines += ["chains across layers:", *(f"  {'stitched-only' if chain.stitched_only else 'single-scenario'} "
                                         f"{chain.layer_path} | {chain.condition}"
                                         + "".join(f"\n    {hop.text}" for hop in chain.hops)
                                         for chain in summary.cross_layer_chains)]
    lines += ["effects below the business layer:", *(f"  {item.layer} {item.effect} caused by {item.causes}"
                                                      for item in summary.layer_effects)]
    lines += ["validations:", *(f"  {'confirmed' if item.confirmed else 'refuted'} {item.selection} "
                                f"{'stitched-only' if item.stitched_only else 'single-scenario'} in {item.workload} "
                                f"hops {''.join('+' if hop else '-' for hop in item.hops)} layers {item.layer_path} "
                                f"random edges {item.random_has_edges} chain {item.random_has_chain}"
                                + "".join(f"\n    {text}" for text in item.hops_text)
                                for item in summary.validations)]
    lines += [f"smallest count increase {summary.min_count_increase}; effect map feedback {summary.feedback}",
              f"edges phased vs random: {None if summary.edges is None else summary.edges.model_dump()}",
              f"single scenarios: {summary.single.model_dump()}"]
    lines += [f"lookup {lookup.query}: " + "; ".join(
        f"{strategy} " + (" ".join(f"held {sorted(edge.held_in)} not {list(edge.not_held)} condition "
                                   f"{condition_text(edge)}" for edge in found) or "absent")
        for strategy, found in lookup.found.items()) for lookup in summary.lookups]
    return "\n".join(lines)
