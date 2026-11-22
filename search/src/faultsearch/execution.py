import json
from hashlib import sha256
from typing import Protocol

from faultpoint.rules import RuleSet
from pydantic import BaseModel, Field

from faultsearch.allocation import Phase
from faultsearch.catalog import FROZEN, Fault
from faultsearch.counterfactual import Group, NamedWorkload, control_labels
from faultsearch.facts import CONTROL_GROUP, FactList, Facts, PathRequest, Purpose, SearchRun


def repetition_seed(label: str) -> int:
    """The FAULTPOINT_SEED of a repetition, from its label, so that the repetitions of one group draw their rules'
    chances anew and a repetition run again draws the same."""
    return int(sha256(label.encode()).hexdigest()[:15], 16)


class RepetitionRequest(BaseModel):
    """One repetition an executor runs for a request: its index and label, the seed its services' rules draw with,
    and the rule set they load, whose experiment is the label."""

    model_config = FROZEN

    index: int
    label: str
    seed: int
    rules: RuleSet


class RunRequest(BaseModel):
    """A group of faults, or a control when there are none, to run in one workload for a number of repetitions, with
    what the plan wants recorded of it."""

    model_config = FROZEN

    workload: NamedWorkload
    faults: tuple[Fault, ...] = ()
    purpose: Purpose
    phases: tuple[Phase, ...] = ()
    """For an edge run, the allocation phase of each fault."""
    requests: tuple[PathRequest, ...] = ()
    """For a path run, the chains that ask for it."""
    repetitions: int = Field(ge=2)

    @property
    def group(self) -> str:
        return Group(workload=self.workload, faults=self.faults).digest if self.faults else CONTROL_GROUP

    def labels(self) -> list[str]:
        if not self.faults:
            return control_labels(self.workload, self.repetitions)
        return Group(workload=self.workload, faults=self.faults).labels(self.repetitions)

    def ruleset(self, label: str) -> RuleSet:
        if not self.faults:
            return RuleSet(experiment=label)
        return Group(workload=self.workload, faults=self.faults).ruleset(label)


class PlannedRequest(BaseModel):
    """A request with every repetition spelled out, so that an executor runs it without computing labels, rules or
    seeds."""

    model_config = FROZEN

    request: RunRequest
    repetitions: tuple[RepetitionRequest, ...]

    @classmethod
    def of(cls, request: RunRequest) -> "PlannedRequest":
        return cls(request=request, repetitions=tuple(
            RepetitionRequest(index=index, label=label, seed=repetition_seed(label), rules=request.ruleset(label))
            for index, label in enumerate(request.labels())))


class Executor(Protocol):
    """What runs a plan's requests: it writes every repetition of every request it can run as a search run to the
    plan's facts and returns those runs, and runs a repetition whose search run it wrote before not again."""

    def run(self, requests: list[RunRequest]) -> list[SearchRun]: ...


class RecordedExecutor:
    """An executor that runs nothing and answers requests from the search runs of other facts, matched by workload,
    group and index: a repetition they hold is written to the plan's facts as a new fact with the request's purpose,
    one they lack is left out and its request's injections are counted as unavailable."""

    def __init__(self, recorded: Facts, log: FactList) -> None:
        self.recorded = {(run.workload.name, run.group, run.index): run for run in recorded.standing_runs()}
        self.log = log
        self.unavailable = 0
        """The injections the requests asked for that the recorded facts lack."""

    def run(self, requests: list[RunRequest]) -> list[SearchRun]:
        found = []
        for request in requests:
            keys = [(request.workload.name, request.group, index) for index in range(request.repetitions)]
            if not all(key in self.recorded for key in keys):
                self.unavailable += max(1, len(request.faults))
                continue
            for key in keys:
                recorded = self.recorded[key]
                if (recorded.source, recorded.label) not in self.log.runs:
                    self.log.append(recorded.model_copy(update={
                        "sequence": self.log.next_sequence(), "purpose": request.purpose, "phases": request.phases,
                        "requests": request.requests}))
                found.append(self.log.runs[(recorded.source, recorded.label)])
        return found


def print_request_schema() -> None:
    """Print the JSON Schema of a run request, which the plan gives and the recording of a repetition reads."""
    print(json.dumps(RunRequest.model_json_schema(), indent=2))
