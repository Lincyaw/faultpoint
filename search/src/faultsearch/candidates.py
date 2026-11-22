import argparse
import json
from pathlib import Path

from pydantic import BaseModel

from faultsearch.catalog import FROZEN, point_service
from faultsearch.chains import Chain
from faultsearch.counterfactual import TreatmentRecord
from faultsearch.edges import Edge, Sighting
from faultsearch.facts import Conclusion, DeviationReference, FailureCategory, PathIdentity, read_facts
from faultsearch.graph import ComputeSettings, FactGraph
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


class CandidatePaths(BaseModel):
    """The candidate paths of the facts up to one sequence number, best first."""

    model_config = FROZEN

    through: int
    paths: tuple[CandidatePath, ...]


def path_identity(chain: Chain, inventory: str) -> PathIdentity:
    """The path a chain stands for, whichever substitutes continue it: its first fault and its hops' effects at the
    points of one point inventory."""
    return PathIdentity(head=chain.hops[0].cause.key,
                        deviations=tuple(DeviationReference(inventory=inventory, point=hop.effect.point,
                                                            effect=hop.effect.key) for hop in chain.hops))


def candidate_path(rank: int, chain: Chain, identity: PathIdentity, graph: FactGraph, edges: dict[str, Edge],
                   path_records: dict[RunKey, TreatmentRecord], appraisals: list[PathAppraisal]) -> CandidatePath:
    """A ranked chain with the evidence of its hops, in the load variants and in its path run, and its judgement."""
    scenarios = graph.variants.scenarios
    record = path_records.get(run_key(chain, scenarios))
    checks = hop_checks(chain, record, graph.settings.min_count_increase) if record else None
    return CandidatePath(
        rank=rank, path=identity, head_service=point_service(chain.hops[0].cause.point), chain=chain.key,
        hops=tuple(CandidateHop(injection=hop.cause.key, deviation=deviation, service=point_service(hop.effect.point),
                                sightings=edges[f"[{hop.cause.key}] {hop.effect.key}"].held,
                                run=checks[index] if checks else None)
                   for index, (hop, deviation) in enumerate(zip(chain.hops, identity.deviations, strict=True))),
        judgement=run_verdict(chain, path_records, scenarios, graph.settings.min_count_increase),
        stitched_only=chain.stitched_only, crosses_layers=chain.crosses_layers, appraisals=tuple(appraisals))


def candidate_paths(graph: FactGraph) -> CandidatePaths:
    """The paths that end in a failure the user sees, from the kept chains stitched with the path runs' judgement:
    those that exist only by stitching and cross layers first, then the others, each in the stitching's order. A path
    a standing appraisal finds failing goes after every other, so that no such appraisal raises its rank; a path
    several chains stand for takes the place of the best of them."""
    stitching = graph.judged_stitching
    order = {key: rank for rank, key in enumerate(stitching.keys)}
    inventory = graph.inventory.identity
    chains = {chain.key: chain for chain in (*stitching.top, *stitching.top_cross_layer) if chain.terminal}
    identities = {key: path_identity(chain, inventory) for key, chain in chains.items()}
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
    return CandidatePaths(through=graph.facts.facts[-1].sequence,
                          paths=tuple(candidate_path(rank, chain, identity, graph, edges, path_records,
                                                     appraised.get(identity, []))
                                      for rank, (identity, chain) in enumerate(best.items(), 1)))


def print_candidate_paths() -> None:
    """Print, as JSON, the candidate paths that the facts of a fact file give under the compute settings of a JSON
    file, best first."""
    parser = argparse.ArgumentParser(description=print_candidate_paths.__doc__)
    parser.add_argument("facts", type=Path, help="A fact file: one fact per line, in sequence order.")
    parser.add_argument("settings", type=Path, help="The compute settings, a JSON object.")
    parser.add_argument("--limit", type=int, default=20, help="The most paths to print, best first.")
    arguments = parser.parse_args()
    found = candidate_paths(FactGraph(read_facts(arguments.facts),
                                      ComputeSettings.model_validate_json(arguments.settings.read_bytes())))
    print(found.model_copy(update={"paths": found.paths[:arguments.limit]}).model_dump_json(indent=2))


def print_schema() -> None:
    """Print the JSON Schema of the candidate paths a fact file gives."""
    print(json.dumps(CandidatePaths.model_json_schema(mode="serialization"), indent=2))
