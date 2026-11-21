from collections import Counter, defaultdict
from collections.abc import Iterable
from enum import StrEnum
from itertools import pairwise
from math import prod
from statistics import fmean
from typing import Final

from pydantic import BaseModel

from faultsearch.allocation import Allocation, Strategy
from faultsearch.catalog import FROZEN, Fault, Layer, point_service
from faultsearch.counterfactual import EffectKey, TreatmentRecord
from faultsearch.edges import Condition, Edge, holds
from faultsearch.evidence import ClassChecks, MappingFeedback, step_classes, step_probability

LAYER_PATH_SEPARATOR: Final = " > "
CROSS_LAYER_KEPT: Final = 300

type Step = tuple[EffectKey, Fault, EffectKey]
"""An effect, the counterpart a chain continues it with, and the consequence the chain expects of the counterpart."""
type Group = tuple[tuple[int, ...], str]
"""The sequence of the clusters of a chain's faults and its path through the layers."""


def confidence(steps: Iterable[Step], checked: dict[str, ClassChecks]) -> float:
    """The estimated chance that validation confirms every step after a chain's first hop, the product of the steps'
    chances, so that a chain resting on more substitutions, or on classes validations refuted, ranks lower."""
    return prod(step_probability(step_classes(*step), checked) for step in steps)


def contradicted_hops(edges: tuple[Edge, ...], witnessed: dict[str, dict[str, set[str]]]) -> tuple[int, ...]:
    """The hops a natural witness contradicts: in a scenario where the hop's counterpart showed the hop's effect, the
    first fault, injected there in every repetition, caused the effect before but not this one, and caused the two
    together in no scenario; a hop in a scenario the first fault was not fully injected in is not judged."""
    natural = witnessed.get(edges[0].cause.key, {})
    return tuple(index for index, (before, edge) in enumerate(pairwise(edges), 1)
                 if not any({before.effect.key, edge.effect.key} <= shown for shown in natural.values())
                 and any(before.effect.key in natural[scenario] and edge.effect.key not in natural[scenario]
                         for scenario in edge.held_in if scenario in natural))


def similarity_order(several_scenarios: bool, similarity: float) -> float:
    """The last ranking criterion, higher first. A chain whose hops need several scenarios ranks dissimilar clusters
    first: clusters whose effects differ from one scenario to another are the sign of conditional causality that
    allocation favours too; other chains rank alike clusters first."""
    return 1 - similarity if several_scenarios else similarity


class Visibility(StrEnum):
    """What the scenarios tested tell of a chain: one of them showed it end to end, none did, or one that did not
    show it injected the first fault in only some repetitions."""

    SINGLE_SCENARIO = "single-scenario"
    STITCHED_ONLY = "stitched-only"
    UNDETERMINED = "undetermined"


class Hop(BaseModel):
    model_config = FROZEN

    cause: Fault
    effect: EffectKey
    held: tuple[str, ...]
    cluster: int
    effect_layer: Layer
    acts_on: str | None = None
    """For a fault no rule can scope, the container or process it reaches the whole of."""

    @property
    def text(self) -> str:
        where = f" on {self.acts_on}" if self.acts_on else ""
        return f"[{self.cause.layer}{where}: {self.cause.key}] -> [{self.effect_layer}: {self.effect.key}]"


def group_of(hops: tuple[Hop, ...]) -> Group:
    """What chains share when they are the same causal path: the clusters of their faults and the layers they cross;
    novelty only groups chains and no longer ranks them."""
    layers = (*(hop.cause.layer for hop in hops), hops[-1].effect_layer)
    return tuple(hop.cluster for hop in hops), LAYER_PATH_SEPARATOR.join(layers)


class Chain(BaseModel):
    """Edges stitched where each effect corresponds to the next edge's fault, with the facts the ranking reads."""

    model_config = FROZEN

    hops: tuple[Hop, ...]
    condition: Condition
    """The parameter values that, merged onto the baseline, should activate every hop."""
    several_scenarios: bool
    """No single tested scenario showed every hop."""
    services: tuple[str, ...]
    terminal: bool
    novel: bool
    """No chain ranked above it is in the same group, so that it stands for the group when validation runs rotate
    over the groups."""
    similarity: float
    """The mean similarity of the clusters of the hops' faults."""
    end_to_end: tuple[str, ...]
    """The scenarios where injecting the first fault alone showed every hop's effect."""
    undetermined: tuple[str, ...] = ()
    """The scenarios that did not show the chain but injected the first fault in only some repetitions, an unfinished
    test that tells neither whether they show it nor whether they do not."""
    confidence: float = 1.0
    """The estimated chance that validation confirms every step after the first hop, from the checks recorded when it
    was stitched; stitchings from before it was estimated give 1."""
    contradicted: tuple[int, ...] = ()
    """The hops a natural witness contradicts."""

    def steps(self) -> list[Step]:
        return [(before.effect, after.cause, after.effect) for before, after in pairwise(self.hops)]

    @property
    def group(self) -> Group:
        return group_of(self.hops)

    @property
    def stitched_only(self) -> bool:
        """Every scenario that tested the first fault in all repetitions failed to show the chain, and no test of it
        was left unfinished."""
        return not self.end_to_end and not self.undetermined

    @property
    def shown(self) -> bool:
        """Some scenario showed the chain end to end."""
        return bool(self.end_to_end)

    @property
    def visibility(self) -> Visibility:
        return (Visibility.SINGLE_SCENARIO if self.shown else Visibility.STITCHED_ONLY if self.stitched_only
                else Visibility.UNDETERMINED)

    @property
    def key(self) -> str:
        return " -> ".join(f"[{hop.cause.key}] {hop.effect.key}" for hop in self.hops)

    @property
    def layers(self) -> tuple[Layer, ...]:
        """The layer of every hop's fault, then of the last effect."""
        return *(hop.cause.layer for hop in self.hops), self.hops[-1].effect_layer

    @property
    def layer_path(self) -> str:
        return LAYER_PATH_SEPARATOR.join(self.layers)

    @property
    def crosses_layers(self) -> bool:
        return len(set(self.layers)) > 1

    def rank(self) -> tuple[bool, int, bool, float, float]:
        return (self.several_scenarios, len(self.services), self.terminal, self.confidence,
                similarity_order(self.several_scenarios, self.similarity))


class Trail(BaseModel):
    """A chain in the beam: its edges and the merged conditions still compatible with all of them."""

    model_config = FROZEN

    edges: tuple[Edge, ...]
    conditions: tuple[Condition, ...]

    def services(self) -> tuple[str, ...]:
        """The services of the hops' faults and of the last effect, leaving out the upstream components, whose
        background work a longer run alone increases."""
        layered = [(edge.cause.point, edge.cause.layer) for edge in self.edges]
        layered.append((self.edges[-1].effect.point, self.edges[-1].effect_layer))
        return tuple(sorted({point_service(point) for point, layer in layered if layer != Layer.UPSTREAM}))

    def several_scenarios(self) -> bool:
        return not frozenset.intersection(*(edge.held_in for edge in self.edges))

    def similarity(self, allocation: Allocation) -> float:
        return fmean(allocation.cluster_of[edge.cause.key].similarity for edge in self.edges)

    def steps(self) -> list[Step]:
        return [(before.effect, after.cause, after.effect) for before, after in pairwise(self.edges)]

    def rank(self, allocation: Allocation, checked: dict[str, ClassChecks]) -> tuple[bool, int, bool, float, float]:
        """The rank of the chain it becomes: needing several scenarios, services crossed, ending in a failure the user
        sees, the chance validation confirms it, and the order of its clusters' similarity to break ties."""
        several = self.several_scenarios()
        order = similarity_order(several, self.similarity(allocation))
        return several, len(self.services()), self.edges[-1].terminal, confidence(self.steps(), checked), order

    def promise(self, allocation: Allocation) -> tuple[bool, int, float]:
        """The rank without ending at the user, which extending a chain still open can only reach later."""
        several = self.several_scenarios()
        return several, len(self.services()), similarity_order(several, self.similarity(allocation))


class Stitching(BaseModel):
    model_config = FROZEN

    strategy: Strategy
    edges: int
    chains: int
    stitched_only: int
    single_scenario: int
    undetermined: int = 0
    """Chains no scenario showed whose first fault one scenario injected in only some repetitions."""
    terminal_stitched_only: int
    stitched_terminal_pairs: tuple[tuple[str, str], ...]
    """The distinct (first fault, failure the user sees) pairs of the stitched-only chains."""
    keys: tuple[str, ...]
    """Every chain found, best ranked first."""
    layer_paths: dict[str, int]
    """How many chains follow each sequence of layers."""
    stitched_layer_paths: dict[str, int]
    """How many of the stitched-only chains follow each sequence of layers."""
    top: tuple[Chain, ...]
    top_cross_layer: tuple[Chain, ...]
    """The best ranked chains whose hops lie in more than one layer and that end in a failure the user sees: as many
    of those that exist only by stitching, then of those one scenario showed, so that neither crowds out the other."""
    cycles: tuple[Chain, ...]
    min_count_increase: float = 0.0
    """The smallest relative increase of a count that counted as an effect."""
    refuted_mappings: tuple[tuple[str, str, str], ...] = ()
    """The (effect, counterpart, consequence) steps that validations refuted and that no chain took."""


def merge_conditions(left: tuple[Condition, ...], right: tuple[Condition, ...]) -> tuple[Condition, ...]:
    """Every union of one condition from each side that sets no parameter to two values."""
    merged: list[Condition] = []
    for first in left:
        for second in right:
            union = {**first, **second}
            if all(first[name] == value for name, value in second.items() if name in first) and union not in merged:
                merged.append(union)
    return tuple(merged)


def beam_search(edges: list[Edge], allocation: Allocation, width: int, max_hops: int,
                refuted: frozenset[tuple[str, str, str]]) -> tuple[list[Trail], list[Trail]]:
    """Chains of two or more compatible edges, extending at every length the most promising chains that do not yet
    end at the user, and the cycles whose last effect corresponds to the first fault; no chain takes a step from an
    effect through a counterpart to a consequence that validations refuted."""
    by_cause: dict[str, list[Edge]] = defaultdict(list)
    for edge in edges:
        if not edge.injected:
            by_cause[edge.cause.key].append(edge)
    beam = [Trail(edges=(edge,), conditions=edge.conditions) for edge in edges
            if edge.counterparts and not edge.terminal]
    chains: list[Trail] = []
    cycles: list[Trail] = []
    for _ in range(max_hops):
        extended = []
        for trail in beam:
            causes = [edge.cause.key for edge in trail.edges]
            for following in sorted({fault.key for fault in trail.edges[-1].counterparts}):
                if following == causes[0] and len(causes) > 1:
                    cycles.append(trail)
                extended += [Trail(edges=(*trail.edges, edge), conditions=conditions) for edge in by_cause[following]
                             if following not in causes
                             and (trail.edges[-1].effect.key, following, edge.effect.key) not in refuted
                             and (conditions := merge_conditions(trail.conditions, edge.conditions))]
        chains += [trail for trail in extended if len(trail.edges) <= max_hops]
        beam = sorted((trail for trail in extended if not trail.edges[-1].terminal),
                      key=lambda trail: trail.promise(allocation), reverse=True)[:width]
    return chains, cycles


def ranked_chains(trails: list[Trail], allocation: Allocation, records: list[TreatmentRecord],
                  min_count_increase: float, checked: dict[str, ClassChecks]) -> list[Chain]:
    """Chains ranked by needing several scenarios, services crossed, ending in a failure the user sees, the chance
    validation confirms them and the order of their cluster similarity, each marked as the first of its group or not
    and with the hops a natural witness contradicts."""
    shown: dict[str, list[tuple[str, set[str]]]] = defaultdict(list)
    witnessed: dict[str, dict[str, set[str]]] = defaultdict(dict)
    unfinished: dict[str, set[str]] = defaultdict(set)
    for record in records:
        effects = {EffectKey.of(effect).key for effect in record.effects if holds(effect, min_count_increase)}
        shown[record.fault.key].append((record.workload, effects))
        if record.exercised:
            witnessed[record.fault.key][record.workload] = effects
        if any(record.injected) and not record.exercised:
            unfinished[record.fault.key].add(record.workload)
    seen: set[Group] = set()
    chains = []
    for trail in sorted(trails, key=lambda trail: trail.rank(allocation, checked), reverse=True):
        hops = tuple(Hop(cause=edge.cause, effect=edge.effect, held=tuple(sorted(edge.held_in)),
                         cluster=allocation.cluster_of[edge.cause.key].number, effect_layer=edge.effect_layer,
                         acts_on=edge.acts_on) for edge in trail.edges)
        effects = {edge.effect.key for edge in trail.edges}
        first = trail.edges[0].cause.key
        end_to_end = tuple(sorted(scenario for scenario, shown_effects in shown[first] if effects <= shown_effects))
        chains.append(Chain(
            hops=hops, condition=trail.conditions[0], several_scenarios=trail.several_scenarios(),
            services=trail.services(), terminal=trail.edges[-1].terminal, novel=group_of(hops) not in seen,
            similarity=trail.similarity(allocation), end_to_end=end_to_end,
            undetermined=tuple(sorted(scenario for scenario in unfinished[first] if scenario not in end_to_end)),
            confidence=confidence(trail.steps(), checked), contradicted=contradicted_hops(trail.edges, witnessed)))
        seen.add(group_of(hops))
    return chains


def stitch(edges: list[Edge], allocation: Allocation, records: list[TreatmentRecord], width: int, max_hops: int,
           kept: int, min_count_increase: float, feedback: MappingFeedback) -> Stitching:
    refuted = feedback.refuted()
    checked = feedback.class_checks()
    trails, cycle_trails = beam_search(edges, allocation, width, max_hops, refuted)
    chains = sorted(ranked_chains(trails, allocation, records, min_count_increase, checked), key=Chain.rank,
                    reverse=True)
    stitched_only = sum(chain.stitched_only for chain in chains)
    terminal = [chain for chain in chains if chain.stitched_only and chain.terminal]
    cross_layer = [chain for chain in chains if chain.crosses_layers and chain.terminal]
    return Stitching(strategy=allocation.strategy, edges=len(edges), chains=len(chains), stitched_only=stitched_only,
                     single_scenario=sum(chain.shown for chain in chains),
                     undetermined=sum(bool(chain.undetermined) and not chain.shown for chain in chains),
                     terminal_stitched_only=len(terminal),
                     stitched_terminal_pairs=tuple(sorted({(chain.hops[0].cause.key, chain.hops[-1].effect.key)
                                                           for chain in terminal})),
                     keys=tuple(chain.key for chain in chains),
                     layer_paths=dict(Counter(chain.layer_path for chain in chains)),
                     stitched_layer_paths=dict(Counter(chain.layer_path for chain in chains if chain.stitched_only)),
                     top=tuple(chains[:kept]),
                     top_cross_layer=tuple(
                         [chain for chain in cross_layer if chain.stitched_only][:CROSS_LAYER_KEPT]
                         + [chain for chain in cross_layer if chain.shown][:CROSS_LAYER_KEPT]),
                     cycles=tuple(ranked_chains(cycle_trails, allocation, records, min_count_increase, checked)),
                     min_count_increase=min_count_increase, refuted_mappings=tuple(sorted(refuted)))
