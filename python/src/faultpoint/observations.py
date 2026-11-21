import os
import socket
import threading
import time
from collections.abc import Iterable, Mapping
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Final, Protocol

from pydantic import BaseModel, Field

from faultpoint.rules import STRICT

JSONL_OPTIONS: Final = "jsonl"
SAMPLED_DIGITS: Final = 8
SAMPLING_BUCKETS: Final = 10_000
NO_DETAIL: Final[Mapping[str, str]] = MappingProxyType({})

type DetailItems = tuple[tuple[str, str], ...]


class DetailKey(StrEnum):
    """The keys of an observation's detail; spec/kinds.json lists those of each kind. Values stay bounded: no
    messages, identifiers or times."""

    STATUS = "status"
    ERROR = "error"
    SENT = "sent"
    ABANDONED = "abandoned"
    CODE = "code"
    VALUE = "value"


def error_type(error: BaseException | type[BaseException]) -> str:
    """The qualified class name of an exception, the error of a detail."""
    kind = error if isinstance(error, type) else type(error)
    return f"{kind.__module__}.{kind.__qualname__}"


def flag(value: bool) -> str:
    return "true" if value else "false"


class Observation(BaseModel):
    """One execution of a point."""

    model_config = STRICT

    experiment: str
    point: str
    outcome: str
    scope: str
    rule: str | None
    quantity: float
    trace_id: str | None
    detail: dict[str, str] = Field(default_factory=dict)


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
    detail: dict[str, str] = Field(default_factory=dict)
    """What else the executions had in common beyond their outcome, by the keys the kind lists, such as the exact
    status or the error type."""


class ObservationSink(Protocol):
    interval: float
    """Seconds between the flushes the runtime asks for."""

    def add(self, observation: Observation) -> None: ...

    def flush(self) -> None: ...

    def forked(self) -> None:
        """Continue in a forked child as a process of its own, without the parent's unwritten observations, which
        the parent writes."""
        ...


def process_identity() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


class JsonlOptions(BaseModel):
    model_config = STRICT

    flush_seconds: float = Field(default=2.0, gt=0)
    exemplars: int = Field(default=5, ge=0)
    exemplar_rate: float = Field(default=1.0, ge=0, le=1)
    """The share of traces whose ids are kept as exemplars, for hot library paths; counts stay exact."""

    def sampled(self, trace_id: str) -> bool:
        """Whether a trace is sampled, by its id, so that every process keeps or skips the same traces."""
        return int(trace_id[-SAMPLED_DIGITS:], 16) % SAMPLING_BUCKETS < self.exemplar_rate * SAMPLING_BUCKETS


class TallyEntry(BaseModel):
    count: int = 0
    total: float = 0.0
    exemplars: list[str] = Field(default_factory=list)


class JsonlSink:
    """Observations aggregated in the process and appended to a JSON Lines file at every flush."""

    def __init__(self, path: Path, service: str, options: JsonlOptions) -> None:
        self.path = path
        self.service = service
        self.process = process_identity()
        self.interval = options.flush_seconds
        self.options = options
        self.lock = threading.Lock()
        self.tally: dict[tuple[str, str, str, str, str | None, DetailItems], TallyEntry] = {}
        self.window_start = time.time()

    def add(self, observation: Observation) -> None:
        key = (observation.experiment, observation.point, observation.outcome, observation.scope,
               observation.rule, tuple(sorted(observation.detail.items())))
        with self.lock:
            entry = self.tally.setdefault(key, TallyEntry())
            entry.count += 1
            entry.total += observation.quantity
            if observation.trace_id is not None and len(entry.exemplars) < self.options.exemplars \
                    and self.options.sampled(observation.trace_id):
                entry.exemplars.append(observation.trace_id)

    def flush(self) -> None:
        end = time.time()
        with self.lock:
            records = [ObservationRecord(
                experiment=experiment, service=self.service, process=self.process,
                start=self.window_start, end=end, point=point, outcome=outcome, scope=scope,
                rule=rule, count=entry.count, total=entry.total, exemplars=tuple(entry.exemplars),
                detail=dict(detail)) for (experiment, point, outcome, scope, rule, detail), entry in self.tally.items()]
            self.tally = {}
            self.window_start = end
            lines = "".join(record.model_dump_json() + "\n" for record in records)
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(lines)

    def forked(self) -> None:
        # A thread of the parent that held the lock at the fork does not exist in the child to release it.
        self.lock = threading.Lock()
        self.process = process_identity()
        self.tally = {}
        self.window_start = time.time()


def read_records(paths: Iterable[Path]) -> list[ObservationRecord]:
    return [ObservationRecord.model_validate_json(line)
            for path in paths for line in path.read_text(encoding="utf-8").splitlines() if line]
