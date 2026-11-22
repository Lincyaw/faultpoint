import argparse
import json
import sys
from abc import abstractmethod
from collections.abc import Iterable
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Final, Literal

from faultpoint.observations import ObservationRecord
from faultpoint.placement import Manifest
from faultpoint.rules import Rule
from pydantic import BaseModel, Field, JsonValue, TypeAdapter, ValidationError, field_serializer

from faultsearch.allocation import Phase
from faultsearch.catalog import FROZEN
from faultsearch.counterfactual import NamedWorkload, Scenarios, Statuses
from faultsearch.validation import Selection

CONTROL_GROUP: Final = "control"
"""The group of a control run, which injects nothing."""
FACTS_FILE: Final = "facts.jsonl"
"""The file of a fact directory: one fact per line, in sequence order."""
CONTENT_EXCLUDED: Final = frozenset({"sequence"})
"""What a fact's content leaves out: its number, which a store that keeps facts of several sources assigns anew."""


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

    experiment: str
    """The experiment of the rule set in force: the run's label, or empty for what a process observed before it loaded
    the run's rules, which a comparison leaves out."""
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

    def record(self) -> ObservationRecord:
        """The tally as one observation record, whose window spans all of its executions."""
        return ObservationRecord(experiment=self.experiment, service=self.service, process=self.process, start=self.start,
                                 end=self.end, point=self.point, outcome=self.outcome, scope=self.scope,
                                 rule=self.rule, count=self.count, total=self.total, elapsed=self.elapsed,
                                 detail=self.detail)


def tallies(records: Iterable[ObservationRecord]) -> tuple[Tally, ...]:
    """Observation records summed by experiment, point, outcome, detail, scope, rule, service and process, in the
    order they first appear, each sum in the order of the records, so that a comparison of the tallies adds what it
    adds of the records in the same order within a run."""
    sums: dict[tuple[str, str, str, str, tuple[tuple[str, str], ...], str, str | None, str], list[float]] = {}
    for record in records:
        key = (record.experiment, record.service, record.process, record.point,
               tuple(sorted(record.detail.items())), record.outcome, record.rule, record.scope)
        if key not in sums:
            sums[key] = [0, 0.0, 0.0, record.start, record.end]
        tally = sums[key]
        tally[0] += record.count
        tally[1] += record.total
        tally[2] += record.elapsed
        tally[3] = min(tally[3], record.start)
        tally[4] = max(tally[4], record.end)
    return tuple(Tally(experiment=experiment, service=service, process=process, point=point, outcome=outcome,
                       detail=dict(detail), scope=scope, rule=rule, count=int(count), total=total, elapsed=elapsed,
                       start=start, end=end)
                 for (experiment, service, process, point, detail, outcome, rule, scope),
                 (count, total, elapsed, start, end) in sums.items())


def canonical(value: JsonValue) -> str:
    """JSON text that two equal values always have: keys sorted, no spaces."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: JsonValue) -> str:
    return sha256(canonical(value).encode()).hexdigest()


class FactBody(BaseModel):
    """What every kind of fact has: a number in its store's order, content without that number, and an identity under
    which a store writes it once."""

    model_config = FROZEN

    sequence: int

    @property
    @abstractmethod
    def identity(self) -> str: ...

    def content(self) -> JsonValue:
        """The fact as JSON without its number, every set sorted, which two facts of one identity must share."""
        return self.model_dump(mode="json", exclude=set(CONTENT_EXCLUDED))

    def same_content(self, other: "FactBody") -> bool:
        return canonical(self.content()) == canonical(other.content())


class PathRequest(BaseModel):
    """A chain that asked for a path run, and how it was chosen."""

    model_config = FROZEN

    chain: str
    selection: Selection


class SearchRun(FactBody):
    """One repetition: the deployment reset, then one workload run to its end under one seed and one intervention,
    an empty one for a control. Its identity is its source, its workload, its group and its index; its results never
    enter the identity."""

    kind: Literal[FactKind.SEARCH_RUN] = FactKind.SEARCH_RUN
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
    observations: tuple[str, ...] = Field(min_length=1)
    """The observation files the tallies come from; every run leaves at least one."""

    @property
    def label(self) -> str:
        return f"{self.workload.name}.{self.group}.{self.index}"

    @property
    def identity(self) -> str:
        return f"{self.source}/{self.label}"

    def records(self) -> list[ObservationRecord]:
        return [tally.record() for tally in self.tallies]


class PointInventory(FactBody):
    """Every point of a system at one revision, SDK build and deployment: those its rewriters' manifests list, with
    their language, actions and the errors each service registers; those its deployment configures; and those the
    control runs it names observe."""

    kind: Literal[FactKind.POINT_INVENTORY] = FactKind.POINT_INVENTORY
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
        return digest(self.model_dump(mode="json", include={"system", "revision", "sdk_build", "deployment",
                                                            "controls"}))


class SystemTopology(FactBody):
    """What computing a system's graph needs to know of its deployment: its upstream components, the service whose
    responses the user sees and which of them are failures, the hosts or unique listening ports that identify RPC
    peers, and what a fault no rule can scope acts on."""

    kind: Literal[FactKind.SYSTEM_TOPOLOGY] = FactKind.SYSTEM_TOPOLOGY
    system: str
    upstream: frozenset[str]
    entry_service: str
    terminal_outcomes: tuple[str, ...]
    ports: dict[str, int]
    hosts: dict[str, str] = Field(default_factory=dict, exclude_if=lambda hosts: not hosts)
    """Explicit URL host ownership; when supplied, unknown hosts have no inferred peer."""
    targets: dict[str, str]

    @field_serializer("upstream")
    def sorted_upstream(self, upstream: frozenset[str]) -> list[str]:
        return sorted(upstream)

    @property
    def identity(self) -> str:
        return digest(self.content())


class LoadVariants(FactBody):
    """A system's baseline workload and its variants."""

    kind: Literal[FactKind.LOAD_VARIANTS] = FactKind.LOAD_VARIANTS
    system: str
    scenarios: Scenarios

    @property
    def identity(self) -> str:
        return digest(self.content())


class PointReference(BaseModel):
    """One point of one point inventory, by the inventory's identity."""

    model_config = FROZEN

    inventory: str
    point: str


class DeviationReference(BaseModel):
    """One deviation of a propagation path: an effect at a point of a point inventory."""

    model_config = FROZEN

    inventory: str
    point: str
    effect: str
    """The deviation's key: its point, outcome, detail and metric."""


class PathIdentity(BaseModel):
    """What a propagation path is, whichever substitute injections reached it: the intervention it starts with and
    the deviations it goes through, in order."""

    model_config = FROZEN

    head: str
    """The key of the fault the path starts with."""
    deviations: tuple[DeviationReference, ...]


class Conclusion(StrEnum):
    """Whether the propagation an appraisal judges takes place."""

    HOLDS = "holds"
    FAILS = "fails"
    CONDITIONAL = "conditional"
    """It takes place only under a condition the appraisal names."""


class FailureCategory(StrEnum):
    """Why a propagation fails."""

    HOP = "hop"
    """One of its hops does not take place in the code."""
    SUBSTITUTION = "substitution"
    """A substitute injection does not reproduce what the natural deviation does."""


class Appraisal(FactBody):
    """An agent's reading of the code behind a propagation path, which ranks and plans but establishes nothing."""

    kind: Literal[FactKind.APPRAISAL] = FactKind.APPRAISAL
    call: str
    index: int
    path: PathIdentity
    conclusion: Conclusion
    category: FailureCategory | None = None
    """For a path that fails, why."""
    condition: str | None = None
    """For a conditional path, what it needs."""
    locations: tuple[str, ...]
    reason: str

    @property
    def identity(self) -> str:
        return f"{self.call}#{self.index}"


class Equivalence(FactBody):
    """Two concrete points that are one point, by a named rule of the code that writes it."""

    kind: Literal[FactKind.EQUIVALENCE] = FactKind.EQUIVALENCE
    left: PointReference
    right: PointReference
    rule: str

    @property
    def identity(self) -> str:
        return digest(self.model_dump(mode="json", include={"left", "right", "rule"}))


class Voiding(FactBody):
    """The facts, named by their identities, that the graph no longer uses, and why; a voiding is never undone, and
    what it voided returns only as new facts."""

    kind: Literal[FactKind.VOIDING] = FactKind.VOIDING
    voided: tuple[str, ...]
    reason: str

    @field_serializer("voided")
    def sorted_voided(self, voided: tuple[str, ...]) -> list[str]:
        return sorted(voided)

    @property
    def identity(self) -> str:
        return digest(self.content())


type Fact = Annotated[SearchRun | PointInventory | SystemTopology | LoadVariants | Appraisal | Equivalence | Voiding,
                      Field(discriminator="kind")]
FACT: Final = TypeAdapter(Fact)


class Facts(BaseModel):
    """A system's facts up to one sequence number, in sequence order."""

    model_config = FROZEN

    facts: tuple[Fact, ...]

    def voided(self) -> set[str]:
        return {identity for fact in self.facts if isinstance(fact, Voiding) for identity in fact.voided}

    def standing_runs(self) -> list[SearchRun]:
        """The search runs no voiding names, in sequence order."""
        voided = self.voided()
        return [fact for fact in self.facts if isinstance(fact, SearchRun) and fact.identity not in voided]

    def appraisals(self) -> list[Appraisal]:
        voided = self.voided()
        return [fact for fact in self.facts if isinstance(fact, Appraisal) and fact.identity not in voided]

    def latest[F: BaseModel](self, kind: type[F]) -> F:
        """The last fact of one kind."""
        found = [fact for fact in self.facts if isinstance(fact, kind)]
        if not found:
            raise ValueError(f"the facts hold no {kind.__name__}")
        return found[-1]

    def holds[F: BaseModel](self, kind: type[F]) -> bool:
        return any(isinstance(fact, kind) for fact in self.facts)


class FactList:
    """Facts appended in sequence order, every fact numbered next and every search run's identity written once."""

    def __init__(self, facts: list[Fact]) -> None:
        self.facts = facts
        self.runs: dict[tuple[str, str], SearchRun] = {(fact.source, fact.label): fact for fact in facts
                                                       if isinstance(fact, SearchRun)}

    def next_sequence(self) -> int:
        return self.facts[-1].sequence + 1 if self.facts else 1

    def append(self, fact: Fact) -> None:
        if fact.sequence != self.next_sequence():
            raise ValueError(f"the next fact is number {self.next_sequence()}, not {fact.sequence}")
        if isinstance(fact, SearchRun) and (fact.source, fact.label) in self.runs:
            raise ValueError(f"the search run {fact.identity} is written already")
        self.facts.append(fact)
        if isinstance(fact, SearchRun):
            self.runs[(fact.source, fact.label)] = fact

    def snapshot(self) -> Facts:
        return Facts(facts=tuple(self.facts))


def write_facts(path: Path, facts: Facts) -> None:
    path.write_text("".join(f"{FACT.dump_json(fact).decode()}\n" for fact in facts.facts), encoding="utf-8")


def read_facts(path: Path) -> Facts:
    return Facts(facts=tuple(FACT.validate_json(line) for line in path.read_text(encoding="utf-8").splitlines()))


class NormalizedFact(BaseModel):
    """A fact as a store outside faultsearch compares it: its kind, its identity and its content."""

    kind: FactKind
    identity: str
    content: JsonValue


def print_schema() -> None:
    """Print the JSON Schema of a fact, the union of every kind tagged by its kind, for the stores that keep facts."""
    print(json.dumps(FACT.json_schema(), indent=2))


def normalize_facts() -> None:
    """Read facts, one per line, from a file or standard input, and print every one's kind, identity and content as
    a line of JSON with its keys sorted; a line that is no valid fact, or a fact whose identity an earlier line holds
    with other content, stops it with an exit status of 1 and the line's number and reason."""
    parser = argparse.ArgumentParser(description=normalize_facts.__doc__)
    parser.add_argument("facts", nargs="?", type=Path, help="A fact file; standard input when left out.")
    arguments = parser.parse_args()
    lines = (arguments.facts.read_text(encoding="utf-8") if arguments.facts else sys.stdin.read()).splitlines()
    seen: dict[str, tuple[int, str]] = {}
    for number, line in enumerate(lines, 1):
        try:
            fact = FACT.validate_json(line)
        except ValidationError as error:
            sys.exit(f"line {number}: not a fact: {error}")
        content = canonical(fact.content())
        if fact.identity in seen and seen[fact.identity][1] != content:
            sys.exit(f"line {number}: the identity {fact.identity} of line {seen[fact.identity][0]} with other content")
        seen.setdefault(fact.identity, (number, content))
        # canonical text, with every key sorted, which pydantic's own dump does not give
        print(canonical(NormalizedFact(kind=fact.kind, identity=fact.identity,
                                       content=fact.content()).model_dump(mode="json")))
