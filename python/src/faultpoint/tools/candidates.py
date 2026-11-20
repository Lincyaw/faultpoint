from collections import Counter, defaultdict
from collections.abc import Iterable

from pydantic import BaseModel

from faultpoint.observations import ObservationRecord
from faultpoint.placement import Manifest, PointEntry
from faultpoint.rules import STRICT


class Candidate(BaseModel):
    """A placed point a run without rules executed, and how often it produced each outcome."""

    model_config = STRICT

    point: PointEntry
    executions: int
    outcomes: dict[str, int]


def executed_candidates(manifests: Iterable[Manifest], records: Iterable[ObservationRecord]) -> list[Candidate]:
    """The points of the manifests that the observations show executing naturally, most executed first."""
    outcomes: defaultdict[str, Counter[str]] = defaultdict(Counter)
    for record in records:
        if record.rule is None:
            outcomes[record.point][record.outcome] += record.count
    found = [Candidate(point=entry, executions=outcomes[entry.id].total(), outcomes=dict(outcomes[entry.id]))
             for manifest in manifests for entry in manifest.points if entry.id in outcomes]
    return sorted(found, key=lambda candidate: -candidate.executions)
