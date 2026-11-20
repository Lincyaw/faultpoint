from collections.abc import Iterable
from pathlib import Path
from typing import Final

from pydantic import BaseModel, Field

from faultpoint.rules import STRICT

EXEMPLAR_LIMIT: Final = 5


class ObservationRecord(BaseModel):
    """How often one point produced one outcome in one scope during one flush window."""

    model_config = STRICT

    experiment: str
    """The experiment of the rule set in force, empty when no rule set was loaded."""
    service: str
    process: str
    start: float
    end: float
    point: str
    outcome: str
    scope: str
    rule: str | None
    """The rule that injected at these executions; none for natural executions."""
    count: int = Field(ge=1)
    total: float
    """The summed quantity of the executions, such as latency in milliseconds or rows."""
    exemplars: tuple[str, ...] = ()
    """Trace ids of some of the executions."""


class TallyEntry(BaseModel):
    count: int = 0
    total: float = 0.0
    exemplars: list[str] = Field(default_factory=list)


class Tally:
    """Observations aggregated in a process between two flushes."""

    def __init__(self) -> None:
        self.entries: dict[tuple[str, str, str, str | None], TallyEntry] = {}

    def add(self, point: str, outcome: str, scope: str, rule: str | None, total: float,
            trace_id: str | None) -> None:
        entry = self.entries.setdefault((point, outcome, scope, rule), TallyEntry())
        entry.count += 1
        entry.total += total
        if trace_id is not None and len(entry.exemplars) < EXEMPLAR_LIMIT:
            entry.exemplars.append(trace_id)

    def drain(self, experiment: str, service: str, process: str, start: float,
              end: float) -> list[ObservationRecord]:
        records = [ObservationRecord(
            experiment=experiment, service=service, process=process, start=start, end=end,
            point=point, outcome=outcome, scope=scope, rule=rule, count=entry.count,
            total=entry.total, exemplars=tuple(entry.exemplars))
            for (point, outcome, scope, rule), entry in self.entries.items()]
        self.entries = {}
        return records


def append_records(path: Path, records: Iterable[ObservationRecord]) -> None:
    lines = "".join(record.model_dump_json() + "\n" for record in records)
    if lines:
        with path.open("a", encoding="utf-8") as stream:
            stream.write(lines)


def read_records(paths: Iterable[Path]) -> list[ObservationRecord]:
    return [ObservationRecord.model_validate_json(line)
            for path in paths for line in path.read_text(encoding="utf-8").splitlines() if line]
