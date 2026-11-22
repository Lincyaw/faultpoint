from collections import defaultdict
from collections.abc import Iterable
from enum import StrEnum
from hashlib import sha256
from typing import Annotated, Final, Literal

from faultpoint.observations import ObservationRecord
from faultpoint.placement import Manifest
from faultpoint.rules import Rule
from pydantic import BaseModel, Field, JsonValue

from faultsearch.allocation import Phase
from faultsearch.catalog import FROZEN
from faultsearch.counterfactual import NamedWorkload, Scenarios, Statuses
from faultsearch.validation import Selection

CONTROL_GROUP: Final = "control"
"""The group of a control run, which injects nothing."""


class FactKind(StrEnum):
    SEARCH_RUN = "search-run"
    POINT_INVENTORY = "point-inventory"
    SYSTEM_TOPOLOGY = "system-topology"
    LOAD_VARIANTS = "load-variants"
    APPRAISAL = "appraisal"
    EQUIVALENCE = "equivalence"
    VOIDING = "voiding"


class Purpose(StrEnum):
    """What a search run is for, which decides what the graph computes from it."""

    EDGE = "edge"
    """A run in a load variant, from which edges are learned."""
    PATH = "path"
    """A run in a merged workload, which judges paths and measures their headroom."""


class Tally(BaseModel):
    """What one point did in one scope of a search run, natural or under one rule: its executions, their summed
    quantity and their summed elapsed milliseconds, and the window they fell in."""

    model_config = FROZEN

    service: str
    process: str
    point: str
    outcome: str
    detail: dict[str, str] = {}
    scope: str
    """The tenant whose baggage the executions carried, empty for none."""
    rule: str | None
    """The rule that injected at the executions; none for natural executions."""
    count: int
    total: float
    elapsed: float
    start: float
    end: float

    def record(self, label: str) -> ObservationRecord:
        """The tally as one observation record of the run, whose window spans all of its executions."""
        return ObservationRecord(experiment=label, service=self.service, process=self.process, start=self.start,
                                 end=self.end, point=self.point, outcome=self.outcome, scope=self.scope,
                                 rule=self.rule, count=self.count, total=self.total, elapsed=self.elapsed,
                                 detail=self.detail)


def tallies(records: Iterable[ObservationRecord]) -> tuple[Tally, ...]:
    """Observation records summed by point, outcome, detail, scope, rule, service and process, in the order they first
    appear, each sum in the order of the records, so that a comparison of the tallies adds what it adds of the records
    in the same order within a run."""
    sums: dict[tuple[str, str, str, tuple[tuple[str, str], ...], str, str | None, str], list[float]] = {}
    for record in records:
        key = (record.service, record.process, record.point, tuple(sorted(record.detail.items())), record.outcome,
               record.rule, record.scope)
        if key not in sums:
            sums[key] = [0, 0.0, 0.0, record.start, record.end]
        tally = sums[key]
        tally[0] += record.count
        tally[1] += record.total
        tally[2] += record.elapsed
        tally[3] = min(tally[3], record.start)
        tally[4] = max(tally[4], record.end)
    return tuple(Tally(service=service, process=process, point=point, outcome=outcome, detail=dict(detail),
                       scope=scope, rule=rule, count=int(count), total=total, elapsed=elapsed, start=start, end=end)
                 for (service, process, point, detail, outcome, rule, scope), (count, total, elapsed, start, end)
                 in sums.items())


class PathRequest(BaseModel):
    """A chain that asked for a path run, and how it was chosen."""

    model_config = FROZEN

    chain: str
    selection: Selection


class SearchRun(BaseModel):
    """One repetition: the deployment reset, then one workload run to its end under one seed and one intervention,
    an empty one for a control. Its identity is its source, its workload, its group and its index; its results never
    enter the identity."""

    model_config = FROZEN

    kind: Literal[FactKind.SEARCH_RUN] = FactKind.SEARCH_RUN
    sequence: int
    source: str
    """The workflow or experiment that produced the run."""
    workload: NamedWorkload
    group: str
    """The digest of the group of faults the run injects, or the control group."""
    index: int
    system: str
    revision: str | None
    """The system's revision, none when the experiment did not record it."""
    sdk_build: str
    """The commit of the SDK the services were built and run with."""
    build: dict[str, JsonValue]
    deployment: dict[str, JsonValue]
    environment: str
    seed: int
    purpose: Purpose
    phases: tuple[Phase, ...] = ()
    """For an edge run, the allocation phase of each fault it injects, in the order of its rules."""
    requests: tuple[PathRequest, ...] = ()
    """For a path run, the chains that asked for it."""
    rules: tuple[Rule, ...]
    tallies: tuple[Tally, ...]
    statuses: Statuses
    refusal: str | None = None
    """What a service said when it refused one of the rules, which then ended the run."""
    observations: tuple[str, ...]
    """The observation files the tallies come from."""

    @property
    def label(self) -> str:
        return f"{self.workload.name}.{self.group}.{self.index}"

    def records(self) -> list[ObservationRecord]:
        return [tally.record(self.label) for tally in self.tallies]


class PointInventory(BaseModel):
    """Every point of a system at one revision, SDK build and deployment: those its rewriters' manifests list, with
    their language, actions and the errors each service registers; those its deployment configures; and those the
    control runs it names observe."""

    model_config = FROZEN

    kind: Literal[FactKind.POINT_INVENTORY] = FactKind.POINT_INVENTORY
    sequence: int
    system: str
    revision: str | None
    sdk_build: str
    deployment: dict[str, JsonValue]
    controls: tuple[str, ...]
    """The labels of the control runs whose observations add points."""
    manifests: tuple[Manifest, ...]
    configured: tuple[str, ...]

    @property
    def identity(self) -> str:
        return sha256(self.model_dump_json(include={"system", "revision", "sdk_build", "deployment",
                                                    "controls"}).encode()).hexdigest()[:12]


class SystemTopology(BaseModel):
    """What computing a system's graph needs to know of its deployment: its upstream components, the service whose
    responses the user sees and which of them are failures, the port each service listens on, which tells the service
    a client point calls, and what a fault no rule can scope acts on."""

    model_config = FROZEN

    kind: Literal[FactKind.SYSTEM_TOPOLOGY] = FactKind.SYSTEM_TOPOLOGY
    sequence: int
    system: str
    upstream: frozenset[str]
    entry_service: str
    terminal_outcomes: tuple[str, ...]
    ports: dict[str, int]
    targets: dict[str, str]


class LoadVariants(BaseModel):
    """A system's baseline workload and its variants."""

    model_config = FROZEN

    kind: Literal[FactKind.LOAD_VARIANTS] = FactKind.LOAD_VARIANTS
    sequence: int
    system: str
    scenarios: Scenarios


class PointReference(BaseModel):
    """One point of one point inventory."""

    model_config = FROZEN

    inventory: str
    point: str


class Conclusion(StrEnum):
    PLAUSIBLE = "plausible"
    IMPLAUSIBLE = "implausible"
    CONDITIONAL = "conditional"
    """Plausible only under a condition the appraisal names."""


class DeviationReference(BaseModel):
    """One deviation of a propagation path: an effect at a point of a point inventory."""

    model_config = FROZEN

    point: PointReference
    effect: str


class Appraisal(BaseModel):
    """An agent's reading of the code behind a propagation path, which ranks and plans but establishes nothing."""

    model_config = FROZEN

    kind: Literal[FactKind.APPRAISAL] = FactKind.APPRAISAL
    sequence: int
    call: str
    index: int
    head: str
    """The intervention the path starts with."""
    deviations: tuple[DeviationReference, ...]
    conclusion: Conclusion
    category: str | None = None
    """For an implausible path, what kind of reason makes it so."""
    condition: str | None = None
    """For a conditional path, what it needs."""
    locations: tuple[str, ...]
    reason: str


class Equivalence(BaseModel):
    """Two concrete points that are one point, by a named rule of the code that writes it."""

    model_config = FROZEN

    kind: Literal[FactKind.EQUIVALENCE] = FactKind.EQUIVALENCE
    sequence: int
    left: PointReference
    right: PointReference
    rule: str


class Voiding(BaseModel):
    """The search runs and equivalences one source wrote up to this fact, which the graph no longer uses; a voiding is
    never undone, and what it voided returns only as new facts."""

    model_config = FROZEN

    kind: Literal[FactKind.VOIDING] = FactKind.VOIDING
    sequence: int
    source: str
    reason: str


type Fact = Annotated[SearchRun | PointInventory | SystemTopology | LoadVariants | Appraisal | Equivalence | Voiding,
                      Field(discriminator="kind")]


class Facts(BaseModel):
    """A system's facts up to one sequence number, in sequence order."""

    model_config = FROZEN

    facts: tuple[Fact, ...]

    def standing_runs(self) -> list[SearchRun]:
        """The search runs no later voiding of their source voids, in sequence order."""
        voided = defaultdict(int)
        for fact in self.facts:
            if isinstance(fact, Voiding):
                voided[fact.source] = max(voided[fact.source], fact.sequence)
        return [fact for fact in self.facts if isinstance(fact, SearchRun) and fact.sequence > voided[fact.source]]

    def latest[F: BaseModel](self, kind: type[F]) -> F:
        """The last fact of one kind."""
        found = [fact for fact in self.facts if isinstance(fact, kind)]
        if not found:
            raise ValueError(f"the facts hold no {kind.__name__}")
        return found[-1]
