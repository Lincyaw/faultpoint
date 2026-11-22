from collections import Counter, defaultdict
from typing import Final

from faultpoint.tools.analysis import Metric
from faultsearch.allocation import Strategy
from faultsearch.catalog import FROZEN, Exclusion, Layer
from faultsearch.chains import LAYER_PATH_SEPARATOR, Chain, Visibility
from faultsearch.counterfactual import EffectKey
from faultsearch.edges import Edge
from faultsearch.facts import CONTROL_GROUP, Purpose
from faultsearch.graph import FactGraph
from faultsearch.validation import Selection
from pydantic import BaseModel

from faultsearch_local.executor import RunSettings
from faultsearch_local.store import REPETITIONS, RUN_SETTINGS, Store

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
    visibility: Visibility
    exercised: bool
    hops: tuple[bool, ...]
    confirmed: bool


class LayerEffect(BaseModel):
    """An effect at a layer below the business code, which the business points alone would never show."""

    model_config = FROZEN

    effect: str
    layer: Layer
    causes: dict[str, int]
    """The faults that caused it, counted by their layer."""


class SingleScenarioView(BaseModel):
    """What single scenarios show end to end without stitching: (first fault, user-visible failure) pairs."""

    model_config = FROZEN

    end_to_end: dict[str, int]
    union: int
    stitched: int
    """Such pairs that the stitched-only chains reach."""
    beyond_single: int
    """Of those, the pairs no single injection of the first fault showed in any scenario it was tested in."""


class EdgeLookup(BaseModel):
    model_config = FROZEN

    query: str
    found: tuple[Edge, ...]


class Summary(BaseModel):
    model_config = FROZEN

    commit: str
    settings: RunSettings
    faults: int
    points: int
    excluded: tuple[Exclusion, ...]
    runs: dict[str, int]
    strategy: StrategySummary
    conditional_examples: tuple[Edge, ...]
    cross_layer_chains: tuple[Chain, ...]
    layer_effects: tuple[LayerEffect, ...]
    validations: tuple[ValidationSummary, ...]
    min_count_increase: float
    feedback: dict[str, int]
    """Validated hops checking a correspondence of the effect map, confirmed and refuted, and the steps stitching
    with the judgement no longer takes."""
    single: SingleScenarioView
    lookups: tuple[EdgeLookup, ...]


def run_counts(store: Store, graph: FactGraph) -> dict[str, int]:
    """The search runs by purpose and kind, and the repetition directories no search run comes from, which an
    interrupted run left."""
    counted = Counter(f"{run.purpose} {'controls' if run.group == CONTROL_GROUP else 'treatments'}"
                      for run in graph.runs)
    labels = {run.label for run in graph.runs}
    left = [path for path in store.path(REPETITIONS).iterdir() if path.name not in labels] \
        if store.has(REPETITIONS) else []
    return {**counted, "repetition directories no search run comes from": len(left)}


def strategy_summary(graph: FactGraph) -> StrategySummary:
    allocation, edges, stitching = graph.allocation, graph.edges, graph.stitching
    tested = Counter(record.fault.key for record in graph.records if record.exercised)
    return StrategySummary(
        strategy=allocation.strategy, injections=len(graph.records), exercised=sum(tested.values()),
        phases=dict(Counter(assignment.phase.value for assignment in allocation.assignments)),
        cluster_sizes=tuple(sorted((len(cluster.members) for cluster in allocation.clusters), reverse=True)),
        edges=len(edges), conditional=sum(bool(edge.not_held) for edge in edges),
        tested_once=sum(tested[edge.cause.key] == 1 for edge in edges),
        counterparts=dict(Counter(edge.counterpart.value for edge in edges)),
        edge_layers=dict(Counter(f"{edge.cause.layer}{LAYER_PATH_SEPARATOR}{edge.effect_layer}" for edge in edges)),
        chains=stitching.chains, stitched_only=stitching.stitched_only, single_scenario=stitching.single_scenario,
        cycles=len(stitching.cycles), layer_paths=stitching.layer_paths,
        stitched_layer_paths=stitching.stitched_layer_paths)


def layer_effects(edges: list[Edge]) -> tuple[LayerEffect, ...]:
    """The effects at the library and upstream layers, those with the most causes first."""
    causes: dict[tuple[str, Layer], Counter[str]] = defaultdict(Counter)
    for edge in edges:
        if edge.effect_layer in (Layer.LIBRARY, Layer.UPSTREAM):
            causes[(edge.effect.key, edge.effect_layer)][edge.cause.layer] += 1
    return tuple(LayerEffect(effect=effect, layer=layer, causes=dict(counted))
                 for (effect, layer), counted in sorted(causes.items(), key=lambda item: -item[1].total()))


def single_scenario_view(graph: FactGraph) -> SingleScenarioView:
    effects = graph.stitcher.effects
    shown: dict[str, set[tuple[str, str]]] = {}
    for record in graph.records:
        shown.setdefault(record.workload, set()).update(
            (record.fault.key, key.key) for key in map(EffectKey.of, record.effects) if effects.terminal(key))
    union = set().union(*shown.values())
    stitched = set(graph.stitching.stitched_terminal_pairs)
    return SingleScenarioView(end_to_end={name: len(pairs) for name, pairs in shown.items()}, union=len(union),
                              stitched=len(stitched), beyond_single=len(stitched - union))


def conditional_examples(edges: list[Edge]) -> tuple[Edge, ...]:
    """Conditional edges that can continue a chain or end one, at most two per learned condition: those ending at
    the user first, then counts before means."""
    useful = sorted((edge for edge in edges if edge.not_held and (edge.terminal or edge.counterparts)),
                    key=lambda edge: (not edge.terminal, edge.effect.metric != Metric.COUNT, -len(edge.held), edge.key))
    by_condition: dict[str, list[Edge]] = defaultdict(list)
    for edge in useful:
        by_condition[condition_text(edge)].append(edge)
    return tuple(edge for examples in by_condition.values() for edge in examples[:EXAMPLES_PER_CONDITION])


def summarise(store: Store, graph: FactGraph, queries: list[str]) -> Summary:
    """The summary of an experiment's graph; a graph without path runs has no validation to summarise."""
    settings = store.load(RunSettings, RUN_SETTINGS)
    catalog = graph.catalog
    judged = any(run.purpose == Purpose.PATH and run.group != CONTROL_GROUP for run in graph.runs)
    validations = graph.judgement[2].validations if judged else ()
    feedback = graph.feedback.checks if judged else ()
    judged_stitching = graph.graph().judged_stitching if judged else graph.stitching
    return Summary(
        commit=settings.commit, settings=settings, faults=len(catalog.faults), points=len(catalog.uses),
        excluded=catalog.excluded, runs=run_counts(store, graph), strategy=strategy_summary(graph),
        conditional_examples=conditional_examples(graph.edges),
        cross_layer_chains=graph.stitching.top_cross_layer[:CROSS_LAYER_SHOWN], layer_effects=layer_effects(graph.edges),
        validations=tuple(ValidationSummary(
            chain=validation.chain.key, hops_text=tuple(hop.text for hop in validation.chain.hops),
            layer_path=validation.chain.layer_path, selection=validation.selection,
            workload=validation.workload.name, visibility=validation.chain.visibility,
            exercised=validation.record.exercised, hops=tuple(hop.confirmed for hop in validation.hops),
            confirmed=validation.confirmed) for validation in validations),
        min_count_increase=graph.settings.min_count_increase,
        feedback={"checks": len(feedback), "confirmed": sum(check.confirmed for check in feedback),
                  "refuted": sum(not check.confirmed for check in feedback),
                  "steps left out of the stitching": len(judged_stitching.refuted_mappings)},
        single=single_scenario_view(graph),
        lookups=tuple(EdgeLookup(query=query, found=tuple(
            edge for edge in graph.edges
            if f"[{query.split(QUERY_SEPARATOR)[0]}] {query.split(QUERY_SEPARATOR)[1]}" == edge.key))
            for query in queries))


def condition_text(edge: Edge) -> str:
    return " or ".join(", ".join(f"{name}={value}" for name, value in condition.items()) or "baseline"
                       for condition in edge.conditions)


def render(summary: Summary) -> str:
    strategy = summary.strategy
    lines = [f"SDK {summary.commit}; {summary.faults} faults over {summary.points} points, "
             f"{len(summary.excluded)} points excluded",
             *(f"  excluded {exclusion.point}: {exclusion.reason}" for exclusion in summary.excluded),
             "search runs: " + ", ".join(f"{name} {count}" for name, count in summary.runs.items()),
             f"{strategy.strategy}: {strategy.injections} injections ({strategy.exercised} exercised) "
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
    lines += ["chains across layers:", *(f"  {chain.visibility} "
                                         f"{chain.layer_path} | {chain.condition}"
                                         + "".join(f"\n    {hop.text}" for hop in chain.hops)
                                         for chain in summary.cross_layer_chains)]
    lines += ["effects below the business layer:", *(f"  {item.layer} {item.effect} caused by {item.causes}"
                                                      for item in summary.layer_effects)]
    lines += ["validations:", *(f"  {'confirmed' if item.confirmed else 'refuted'} {item.selection} "
                                f"{item.visibility} in {item.workload} "
                                f"hops {''.join('+' if hop else '-' for hop in item.hops)} layers {item.layer_path}"
                                + "".join(f"\n    {text}" for text in item.hops_text)
                                for item in summary.validations)]
    lines += [f"smallest count increase {summary.min_count_increase}; effect map feedback {summary.feedback}",
              f"single scenarios: {summary.single.model_dump()}"]
    lines += [f"lookup {lookup.query}: " + (" ".join(f"held {sorted(edge.held_in)} not {list(edge.not_held)} "
                                                     f"condition {condition_text(edge)}" for edge in lookup.found)
                                           or "absent") for lookup in summary.lookups]
    return "\n".join(lines)
