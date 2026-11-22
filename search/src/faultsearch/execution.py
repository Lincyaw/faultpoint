from typing import Protocol

from faultpoint.rules import RuleSet
from pydantic import BaseModel, Field

from faultsearch.allocation import Phase
from faultsearch.catalog import FROZEN, Fault
from faultsearch.counterfactual import Group, NamedWorkload, control_labels
from faultsearch.facts import CONTROL_GROUP, PathRequest, Purpose, SearchRun


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


class Executor(Protocol):
    """What runs a plan's requests: it returns every repetition of every request as a search run, and runs a
    repetition whose search run it wrote before not again but returns that run."""

    def run(self, requests: list[RunRequest]) -> list[SearchRun]: ...
