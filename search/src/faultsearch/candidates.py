import argparse
import json
from pathlib import Path

from pydantic import BaseModel, Field

from faultsearch.catalog import FROZEN, point_service
from faultsearch.chains import Chain
from faultsearch.counterfactual import TreatmentRecord
from faultsearch.edges import Edge, Sighting
from faultsearch.facts import (
    Conclusion,
    DeviationReference,
    Facts,
    FailureCategory,
    LoadVariants,
    PathIdentity,
    PointInventory,
    SystemTopology,
    read_facts,
)
from faultsearch.graph import ComputeSettings, EquivalentGraphs, FactGraph
from faultsearch.natural import NaturalJudgement
from faultsearch.validation import HopCheck, RunKey, RunVerdict, hop_checks, run_key, run_verdict


class CandidateHop(BaseModel):
    """One hop of a candidate path: the injection that caused it, the deviation it reached, and what showed it."""

    model_config = FROZEN

    injection: str
    """The key of the fault the hop injects: the path's head for the first hop, after it a substitute for the
    deviation before."""
    deviation: DeviationReference
    service: str
    """The service of the deviation's point."""
    sightings: tuple[Sighting, ...]
    """The load variants where the injection caused the deviation, each with the control and treatment values of the
    comparison that showed it."""
    run: HopCheck | None
    """Whether the deviation appeared in the path run, when one ran."""


class PathAppraisal(BaseModel):
    """What one standing appraisal concluded of a candidate path."""

    model_config = FROZEN

    identity: str
    conclusion: Conclusion
    category: FailureCategory | None


class CandidatePath(BaseModel):
    model_config = FROZEN

    rank: int
    """From 1."""
    path: PathIdentity
    head_service: str
    """The service of the point of the intervention the path starts with."""
    chain: str
    """The key of the chain the path takes its rank from, the best ranked of those that stand for it."""
    hops: tuple[CandidateHop, ...]
    judgement: RunVerdict
    stitched_only: bool
    """No load variant showed the path end to end: it exists only by stitching."""
    crosses_layers: bool
    appraisals: tuple[PathAppraisal, ...]
    natural: tuple[NaturalJudgement, ...] = Field(default=(), exclude_if=lambda runs: not runs)


class CandidatePaths(BaseModel):
    """The candidate paths of the facts up to one sequence number, best first."""

    model_config = FROZEN

    through: int
    paths: tuple[CandidatePath, ...]


def candidate_path(rank: int, chain: Chain, identity: PathIdentity, graph: FactGraph, edges: dict[str, Edge],
                   path_records: dict[RunKey, TreatmentRecord], appraisals: list[PathAppraisal]) -> CandidatePath:
    """A ranked chain with the evidence of its hops, in the load variants and in its path run, and its judgement."""
    scenarios = graph.variants.scenarios
    record = path_records.get(run_key(chain, scenarios))
    checks = hop_checks(chain, record, graph.settings.min_count_increase) if record else None
    natural = tuple(run for run in graph.natural if run.path == identity)
    completed = [run for run in natural if run.judgement != RunVerdict.NEEDS_RUN]
    judgement = run_verdict(chain, path_records, scenarios, graph.settings.min_count_increase)
    if completed:
        checks = completed[-1].hops
        judgement = completed[-1].judgement
    return CandidatePath(
        rank=rank, path=identity, head_service=point_service(chain.hops[0].cause.point), chain=chain.key,
        hops=tuple(CandidateHop(injection=hop.cause.key, deviation=deviation, service=point_service(hop.effect.point),
                                sightings=edges[f"[{hop.cause.key}] {hop.effect.key}"].held,
                                run=checks[index] if checks else None)
                   for index, (hop, deviation) in enumerate(zip(chain.hops, identity.deviations, strict=True))),
        judgement=judgement, natural=natural, stitched_only=chain.stitched_only,
        crosses_layers=chain.crosses_layers, appraisals=tuple(appraisals))


def inventory_candidates(graph: FactGraph) -> tuple[CandidatePath, ...]:
    """The measured paths of one inventory, retaining its point identities and independent comparisons."""
    stitching = graph.judged_stitching
    order = {key: rank for rank, key in enumerate(stitching.keys)}
    inventory = graph.inventory.identity
    chains = {chain.key: chain for chain in (*stitching.top, *stitching.top_cross_layer) if chain.terminal}
    identities = {key: PathIdentity.from_chain(chain, inventory) for key, chain in chains.items()}
    appraised: dict[PathIdentity, list[PathAppraisal]] = {}
    for appraisal in graph.facts.appraisals():
        appraised.setdefault(appraisal.path, []).append(PathAppraisal(
            identity=appraisal.identity, conclusion=appraisal.conclusion, category=appraisal.category))
    failing = {path for path, found in appraised.items() if any(one.conclusion == Conclusion.FAILS for one in found)}
    best: dict[PathIdentity, Chain] = {}
    for chain in sorted(chains.values(), key=lambda chain: (identities[chain.key] in failing,
                                                            not (chain.stitched_only and chain.crosses_layers),
                                                            order[chain.key])):
        best.setdefault(identities[chain.key], chain)
    edges = {edge.key: edge for edge in graph.edges}
    path_records = {(record.fault.key, record.workload): record for record in graph.judgement[0]}
    return tuple(candidate_path(rank, chain, identity, graph, edges, path_records,
                                                     appraised.get(identity, []))
                                      for rank, (identity, chain) in enumerate(best.items(), 1))


def candidate_paths(facts: Facts, settings: ComputeSettings) -> CandidatePaths:
    """All standing inventories' paths, ranked without treating their bare point strings as equivalent."""
    if not all(facts.holds(kind) for kind in (SystemTopology, LoadVariants, PointInventory)):
        return CandidatePaths(through=facts.facts[-1].sequence if facts.facts else 0, paths=())
    measured = EquivalentGraphs(facts, settings)
    paths = [path for graph in measured.graphs.values() for path in inventory_candidates(graph)]
    paths.extend(equivalence_candidates(measured))
    sequences = {run.identity: run.sequence for run in facts.standing_runs()}
    for index, path in enumerate(paths):
        additional = tuple(run for run in measured.natural if run.path == path.path and run not in path.natural)
        if additional:
            natural = tuple(sorted((*path.natural, *additional),
                                   key=lambda judgement: max(sequences[run] for run in judgement.runs)))
            completed = [run for run in natural if run.judgement != RunVerdict.NEEDS_RUN]
            paths[index] = path.model_copy(update={"natural": natural,
                "judgement": completed[-1].judgement if completed else path.judgement,
                "hops": tuple(hop.model_copy(update={"run": completed[-1].hops[number]})
                              for number, hop in enumerate(path.hops)) if completed else path.hops})
    paths.sort(key=lambda path: (any(appraisal.conclusion == Conclusion.FAILS for appraisal in path.appraisals),
                                 not (path.stitched_only and path.crosses_layers)))
    return CandidatePaths(through=facts.facts[-1].sequence,
        paths=tuple(path.model_copy(update={"rank": rank}) for rank, path in enumerate(paths, 1)))


def equivalence_candidates(measured: EquivalentGraphs) -> tuple[CandidatePath, ...]:
    joined = measured.equivalence_graph
    if joined is None:
        return ()
    edges = {(edge.inventory, edge.cause.key, edge.effect.key): edge for edge in joined.edges}
    best: dict[PathIdentity, Chain] = {}
    for chain in joined.chains:
        if chain.terminal:
            best.setdefault(PathIdentity.from_chain(chain, ""), chain)
    candidates: list[CandidatePath] = []
    sequences = {run.identity: run.sequence for run in measured.facts.standing_runs()}
    for identity, chain in best.items():
        judgement = RunVerdict.NEEDS_RUN
        checks = None
        last_sequence = 0
        for target in measured.targets(chain):
            graph = measured.graphs[target.inventory]
            records = {(record.fault.key, record.workload): record for record in graph.judgement[0]}
            verdict = run_verdict(target.chain, records, graph.variants.scenarios,
                                  measured.settings.min_count_increase)
            if verdict != RunVerdict.NEEDS_RUN:
                record = records[run_key(target.chain, graph.variants.scenarios)]
                sequence = max(sequences[label] for label in record.labels)
                if sequence > last_sequence:
                    last_sequence, judgement = sequence, verdict
                    checks = tuple(hop.model_copy(update={"effect": chain.hops[index].effect}) for index, hop in
                        enumerate(hop_checks(target.chain, record, measured.settings.min_count_increase)))
        natural = tuple(run for run in measured.natural if run.path == identity)
        completed = [run for run in natural if run.judgement != RunVerdict.NEEDS_RUN]
        if completed:
            judgement, checks = completed[-1].judgement, completed[-1].hops
        candidates.append(CandidatePath(rank=len(candidates) + 1, path=identity,
            head_service=point_service(chain.hops[0].cause.point), chain=chain.key,
            hops=tuple(CandidateHop(injection=hop.cause.key, deviation=deviation,
                service=point_service(hop.effect.point), sightings=edges[(hop.inventory, hop.cause.key, hop.effect.key)].held,
                run=checks[index] if checks else None)
                for index, (hop, deviation) in enumerate(zip(chain.hops, identity.deviations, strict=True))),
            judgement=judgement, stitched_only=chain.stitched_only, crosses_layers=chain.crosses_layers,
            appraisals=tuple(PathAppraisal(identity=appraisal.identity, conclusion=appraisal.conclusion,
                                          category=appraisal.category)
                             for appraisal in measured.facts.appraisals() if appraisal.path == identity), natural=natural))
    return tuple(candidates)


def print_candidate_paths() -> None:
    """Print, as JSON, the candidate paths that the facts of a fact file give under the compute settings of a JSON
    file, best first."""
    parser = argparse.ArgumentParser(description=print_candidate_paths.__doc__)
    parser.add_argument("facts", type=Path, help="A fact file: one fact per line, in sequence order.")
    parser.add_argument("settings", type=Path, help="The compute settings, a JSON object.")
    parser.add_argument("--limit", type=int, help="The most paths to print, best first; every path when left out.")
    arguments = parser.parse_args()
    found = candidate_paths(read_facts(arguments.facts),
                            ComputeSettings.model_validate_json(arguments.settings.read_bytes()))
    print(found.model_copy(update={"paths": found.paths[:arguments.limit]}).model_dump_json(indent=2))


def print_schema() -> None:
    """Print the JSON Schema of the candidate paths a fact file gives."""
    print(json.dumps(CandidatePaths.model_json_schema(mode="serialization"), indent=2))
