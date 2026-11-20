from collections import defaultdict
from statistics import fmean

from pydantic import BaseModel

from faultsearch.allocation import Allocation, Strategy
from faultsearch.catalog import FROZEN, Fault, point_service
from faultsearch.edges import Condition, Edge, EffectKey
from faultsearch.fca import TreatmentRecord


class Hop(BaseModel):
    model_config = FROZEN

    cause: Fault
    effect: EffectKey
    held: tuple[str, ...]
    cluster: int


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
    """No chain ranked above it has the same sequence of clusters."""
    sim_score: float
    end_to_end: tuple[str, ...]
    """The scenarios where injecting the first fault alone showed every hop's effect."""

    @property
    def stitched_only(self) -> bool:
        return not self.end_to_end

    @property
    def key(self) -> str:
        return " -> ".join(f"[{hop.cause.key}] {hop.effect.key}" for hop in self.hops)

    def rank(self) -> tuple[bool, int, bool, bool, float]:
        return self.several_scenarios, len(self.services), self.terminal, self.novel, self.sim_score


class Trail(BaseModel):
    """A chain in the beam: its edges and the merged conditions still compatible with all of them."""

    model_config = FROZEN

    edges: tuple[Edge, ...]
    conditions: tuple[Condition, ...]

    def services(self) -> tuple[str, ...]:
        return tuple(sorted({point_service(edge.cause.point) for edge in self.edges}
                            | {point_service(self.edges[-1].effect.point)}))

    def several_scenarios(self) -> bool:
        return not frozenset.intersection(*(edge.held_in for edge in self.edges))

    def sim_score(self, allocation: Allocation) -> float:
        return fmean(allocation.cluster_of[edge.cause.key].sim_score for edge in self.edges)

    def rank(self, allocation: Allocation) -> tuple[bool, int, bool, float]:
        return self.several_scenarios(), len(self.services()), self.edges[-1].terminal, self.sim_score(allocation)

    def promise(self, allocation: Allocation) -> tuple[bool, int, float]:
        """The rank without ending at the user, which extending a chain still open can only reach later."""
        return self.several_scenarios(), len(self.services()), self.sim_score(allocation)


class Stitching(BaseModel):
    model_config = FROZEN

    strategy: Strategy
    edges: int
    chains: int
    stitched_only: int
    single_scenario: int
    terminal_stitched_only: int
    stitched_terminal_pairs: tuple[tuple[str, str], ...]
    """The distinct (first fault, failure the user sees) pairs of the stitched-only chains."""
    keys: tuple[str, ...]
    """Every chain found, best ranked first."""
    top: tuple[Chain, ...]
    cycles: tuple[Chain, ...]


def merge_conditions(left: tuple[Condition, ...], right: tuple[Condition, ...]) -> tuple[Condition, ...]:
    """Every union of one condition from each side that sets no parameter to two values."""
    merged: list[Condition] = []
    for first in left:
        for second in right:
            union = {**first, **second}
            if all(first[name] == value for name, value in second.items() if name in first) and union not in merged:
                merged.append(union)
    return tuple(merged)


def beam_search(edges: list[Edge], allocation: Allocation, width: int,
                max_hops: int) -> tuple[list[Trail], list[Trail]]:
    """Chains of two or more compatible edges, extending at every length the most promising chains that do not yet
    end at the user, and the cycles whose last effect corresponds to the first fault."""
    by_cause: dict[str, list[Edge]] = defaultdict(list)
    for edge in edges:
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
                             and (conditions := merge_conditions(trail.conditions, edge.conditions))]
        chains += [trail for trail in extended if len(trail.edges) <= max_hops]
        beam = sorted((trail for trail in extended if not trail.edges[-1].terminal),
                      key=lambda trail: trail.promise(allocation), reverse=True)[:width]
    return chains, cycles


def ranked_chains(trails: list[Trail], allocation: Allocation, records: list[TreatmentRecord]) -> list[Chain]:
    """Chains ranked by needing several scenarios, services crossed, ending in a failure the user sees, novelty of
    their cluster sequence and SimScore; novelty is judged against the chains ranked above."""
    shown: dict[str, list[tuple[str, set[str]]]] = defaultdict(list)
    for record in records:
        shown[record.fault.key].append((record.workload, {EffectKey.of(effect).key for effect in record.effects}))
    seen: set[tuple[int, ...]] = set()
    chains = []
    for trail in sorted(trails, key=lambda trail: trail.rank(allocation), reverse=True):
        clusters = tuple(allocation.cluster_of[edge.cause.key].number for edge in trail.edges)
        effects = {edge.effect.key for edge in trail.edges}
        chains.append(Chain(
            hops=tuple(Hop(cause=edge.cause, effect=edge.effect, held=tuple(sorted(edge.held_in)),
                           cluster=allocation.cluster_of[edge.cause.key].number) for edge in trail.edges),
            condition=trail.conditions[0], several_scenarios=trail.several_scenarios(), services=trail.services(),
            terminal=trail.edges[-1].terminal, novel=clusters not in seen, sim_score=trail.sim_score(allocation),
            end_to_end=tuple(sorted(scenario for scenario, shown_effects in shown[trail.edges[0].cause.key]
                                    if effects <= shown_effects))))
        seen.add(clusters)
    return sorted(chains, key=Chain.rank, reverse=True)


def stitch(edges: list[Edge], allocation: Allocation, records: list[TreatmentRecord], width: int, max_hops: int,
           kept: int) -> Stitching:
    trails, cycle_trails = beam_search(edges, allocation, width, max_hops)
    chains = ranked_chains(trails, allocation, records)
    stitched_only = sum(chain.stitched_only for chain in chains)
    terminal = [chain for chain in chains if chain.stitched_only and chain.terminal]
    return Stitching(strategy=allocation.strategy, edges=len(edges), chains=len(chains), stitched_only=stitched_only,
                     single_scenario=len(chains) - stitched_only, terminal_stitched_only=len(terminal),
                     stitched_terminal_pairs=tuple(sorted({(chain.hops[0].cause.key, chain.hops[-1].effect.key)
                                                           for chain in terminal})),
                     keys=tuple(chain.key for chain in chains), top=tuple(chains[:kept]),
                     cycles=tuple(ranked_chains(cycle_trails, allocation, records)))
