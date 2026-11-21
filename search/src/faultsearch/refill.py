from collections import defaultdict
from typing import Final

from pydantic import BaseModel
from scipy.stats import entropy

from faultsearch.allocation import Allocation, Assignment, Exploration, Phase, Strategy
from faultsearch.catalog import FROZEN, Fault, Layer, point_kind, point_service
from faultsearch.chains import Stitcher, Stitching, Trail, confidence, merge_conditions, similarity_order
from faultsearch.counterfactual import EffectKey
from faultsearch.edges import Edge, counterpart_assignments, holds
from faultsearch.evidence import MappingFeedback, smoothed, step_classes, step_probability

SHORTLIST: Final = 20
"""The best candidate chains, stitched or hypothesised, whose hypothesised hops the candidate phase decides."""
USER_FAILURE_LAYER: Final = Layer.BUSINESS
"""The layer of a failure the user sees: a response of the entry service's server points, which are business code."""
REFILLS: Final = frozenset({Phase.COUNTERPART, Phase.CANDIDATE})

type Rank = tuple[bool, int, bool, float, float]


def stitched(exploration: Exploration, strategy: Strategy, stitcher: Stitcher) -> tuple[Allocation, list[Edge],
                                                                                       Stitching]:
    """The allocation, edges and chains of the exploration's records so far, before any validation."""
    allocation = exploration.allocation(strategy)
    records = [exploration.records[(assignment.fault.key, assignment.scenario)]
               for assignment in allocation.assignments]
    edges = stitcher.edges(records)
    return allocation, edges, stitcher.chains(edges, allocation, records, MappingFeedback(checks=()))


def counterpart_rounds(exploration: Exploration, budget: int, strategy: Strategy, stitcher: Stitcher) -> int:
    """Counterpart refills in rounds within a budget, as the complete command runs them: every round learns the edges
    of the records so far and injects, in random order, the counterparts they need that no injection tried; returns
    the injections spent."""
    spent = 0
    while spent < budget:
        allocation = exploration.allocation(strategy)
        edges = stitcher.edges([exploration.records[(assignment.fault.key, assignment.scenario)]
                                for assignment in allocation.assignments])
        needed = counterpart_assignments(edges, exploration.tried(), exploration.catalog)
        if not needed:
            break
        exploration.rng.shuffle(needed)
        chosen = needed[:budget - spent]
        exploration.run(chosen)
        spent += len(chosen)
    return spent


def counterpart_class(fault: Fault) -> str:
    """The class whose refills tell how likely a counterpart is to cause a failure the user sees: its action, its kind
    of point and its service."""
    return f"{fault.action.kind} at {point_kind(fault.point)} in {point_service(fault.point)}"


def user_failures(exploration: Exploration, stitcher: Stitcher) -> dict[str, tuple[int, int]]:
    """For every class of counterpart, how many of its refills caused a failure the user sees and how many did not."""
    counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for assignment in exploration.assignments:
        record = exploration.records[(assignment.fault.key, assignment.scenario)]
        if assignment.phase in REFILLS and record.exercised:
            failed = any(stitcher.effects.terminal(EffectKey.of(effect))
                         and holds(effect, stitcher.min_count_increase) for effect in record.effects)
            counts[counterpart_class(assignment.fault)][0 if failed else 1] += 1
    return {name: (failed, other) for name, (failed, other) in counts.items()}


class Hypothesis(BaseModel):
    """A candidate chain whose last hop no run has shown yet: stitched edges, then the counterpart of the last effect
    injected in a scenario no injection of it tried, supposed to cause a failure the user sees there."""

    model_config = FROZEN

    prefix: tuple[Edge, ...]
    counterpart: Fault
    scenario: str
    chance: float
    """The hop's estimated chance: that a counterpart of its class causes a failure the user sees, times that
    validation confirms the step."""
    rest: float
    """The estimated chance of the prefix's steps."""
    rank: Rank
    pairs: tuple[Assignment, ...]
    """The injections not tried yet that decide the hop: the counterpart in the scenario, and in the scenarios where
    the effect held, where the acceptance compares it with the natural run."""


def prefixes(edges: list[Edge], stitching: Stitching) -> list[Trail]:
    """Every edge and stitched chain not ending at the user whose last effect a counterpart could continue."""
    by_key = {edge.key: edge for edge in edges}
    singles = [Trail(edges=(edge,), conditions=edge.conditions) for edge in edges
               if edge.counterparts and not edge.terminal]
    return singles + [Trail(edges=tuple(by_key[f"[{hop.cause.key}] {hop.effect.key}"] for hop in chain.hops),
                            conditions=(chain.condition,)) for chain in stitching.top if not chain.terminal]


def hypothesis(trail: Trail, fault: Fault, scenario: str, allocation: Allocation, tried: set[tuple[str, str]],
               stitcher: Stitcher, failures: dict[str, tuple[int, int]]) -> Hypothesis:
    """A prefix continued by a counterpart in a scenario to a supposed failure the user sees, ranked by the keys that
    rank stitched chains, with the hop's chance in place of its confirmation estimate."""
    last = trail.edges[-1]
    entry = stitcher.effects.entry_service
    several = scenario not in frozenset.intersection(*(edge.held_in for edge in trail.edges))
    services = {point_service(cause.point) for cause in (*(edge.cause for edge in trail.edges), fault)
                if cause.layer != Layer.UPSTREAM} | {entry}
    chance = smoothed(*failures.get(counterpart_class(fault), (0, 0))) * step_probability(
        step_classes(last.effect, fault, entry), {})
    rest = confidence(trail.steps(), {})
    pairs = {Assignment(fault=fault, scenario=name, phase=Phase.CANDIDATE) for name in {scenario, *last.held_in}
             if (fault.key, name) not in tried}
    return Hypothesis(prefix=trail.edges, counterpart=fault, scenario=scenario, chance=chance, rest=rest,
                      rank=(several, len(services), True, rest * chance,
                            similarity_order(several, trail.similarity(allocation))),
                      pairs=tuple(sorted(pairs, key=lambda pair: pair.scenario)))


def hypotheses(allocation: Allocation, edges: list[Edge], stitching: Stitching, exploration: Exploration,
               stitcher: Stitcher) -> list[Hypothesis]:
    """Every prefix continued by one of its last effect's accepted counterparts in a scenario that executes its point
    and that no injection of it tried, where the prefix's conditions allow, across layers."""
    failures = user_failures(exploration, stitcher)
    tried = exploration.tried()
    found = []
    for trail in prefixes(edges, stitching):
        last = trail.edges[-1]
        causes = {edge.cause.key for edge in trail.edges}
        found += [hypothesis(trail, fault, scenario, allocation, tried, stitcher, failures)
                  for fault in last.counterparts if fault.key not in last.mismatched and fault.key not in causes
                  for scenario in exploration.catalog.scenarios_executing(fault, exploration.order)
                  if (fault.key, scenario) not in tried
                  and merge_conditions(trail.conditions, (stitcher.scenarios.named(scenario).changes,))
                  and len({*(edge.cause.layer for edge in trail.edges), fault.layer, USER_FAILURE_LAYER}) > 1]
    return found


def candidate_batch(found: list[Hypothesis], stitching: Stitching, size: int) -> list[Assignment]:
    """The injections deciding the hypothesised hops among the best candidate chains, stitched and hypothesised ranked
    together, by expected information per injection: each hop's binary entropy weighted by the chance of the rest of
    its chain, summed over the chains a counterpart in a scenario decides, over the injections that takes."""
    stitched_ranks: list[tuple[Rank, Hypothesis | None]] = [
        (chain.rank(), None) for chain in stitching.top_cross_layer if chain.stitched_only]
    best = sorted([*stitched_ranks, *((found_one.rank, found_one) for found_one in found)],
                  key=lambda entry: entry[0], reverse=True)[:SHORTLIST]
    units: dict[tuple[str, str], tuple[set[Assignment], list[float]]] = defaultdict(lambda: (set(), []))
    for _, chosen in best:
        if chosen is not None:
            pairs, gains = units[(chosen.counterpart.key, chosen.scenario)]
            pairs.update(chosen.pairs)
            gains.append(chosen.rest * float(entropy([chosen.chance, 1 - chosen.chance], base=2)))
    batch: list[Assignment] = []
    for pairs, gains in sorted(units.values(), key=lambda unit: sum(unit[1]) / len(unit[0]), reverse=True):
        if batch and len(batch) + len(pairs) > size:
            break
        batch += sorted(pairs - set(batch), key=lambda pair: (pair.fault.key, pair.scenario))
    return batch[:size]


def candidate_phase(exploration: Exploration, budget: int, strategy: Strategy, stitcher: Stitcher) -> int:
    """The candidate phase within a budget: batches of the injections that decide the hypothesised hops of the best
    candidate chains, stitching again after each, until the budget is spent or no hypothesis is among the best;
    returns the injections spent."""
    spent = 0
    while spent < budget:
        allocation, edges, stitching = stitched(exploration, strategy, stitcher)
        batch = candidate_batch(hypotheses(allocation, edges, stitching, exploration, stitcher), stitching,
                                min(exploration.settings.batch, budget - spent))
        if not batch:
            break
        exploration.run(batch)
        spent += len(batch)
    return spent
