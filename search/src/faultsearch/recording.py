import argparse
import json
from pathlib import Path
from typing import Final

from faultpoint.observations import ObservationRecord, read_records
from faultpoint.rules import RuleSet
from pydantic import BaseModel, JsonValue, TypeAdapter

from faultsearch.allocation import Phase
from faultsearch.catalog import FROZEN, read_manifests
from faultsearch.counterfactual import DEFAULT_SEED, NamedWorkload, Statuses
from faultsearch.execution import RunRequest, repetition_seed
from faultsearch.facts import (
    CONTROL_GROUP,
    FACT,
    Facts,
    NaturalPath,
    PathRequest,
    PointInventory,
    Purpose,
    RunContext,
    SearchRun,
    canonical,
    read_facts,
    tallies,
)

RULES_FILE: Final = "rules.json"
WORKLOAD_FILE: Final = "workload.json"
INSTRUMENTATION_FILE: Final = "instrumentation.json"
SEED_FILE: Final = "seed.txt"
STATUSES_FILE: Final = "statuses.json"
REFUSAL_FILE: Final = "refusal.txt"
OBSERVATIONS: Final = "*.jsonl"
PARAMETERS: Final = TypeAdapter(dict[str, JsonValue])


class RunFile(BaseModel):
    """A file an executor leaves in the run directory of one repetition."""

    model_config = FROZEN

    name: str
    """Its name, or the pattern of the names of the observation files."""
    required: bool
    content: str
    json_schema: dict[str, JsonValue] | None
    """The JSON Schema of its content, or of every line of a JSON Lines file; none for text."""


RUN_FILES: Final = (
    RunFile(name=RULES_FILE, required=True, json_schema=RuleSet.model_json_schema(),
            content="The rule set the services loaded: the repetition's rules, with the label as experiment."),
    RunFile(name=WORKLOAD_FILE, required=True, json_schema=PARAMETERS.json_schema(),
            content="The workload parameters the load ran with."),
    RunFile(name=INSTRUMENTATION_FILE, required=True, json_schema=PARAMETERS.json_schema(),
            content="The deployment configuration: what of faultpoint runs and what the kernel agent observes."),
    RunFile(name=SEED_FILE, required=True, json_schema=None,
            content="The FAULTPOINT_SEED the services ran with, a decimal integer; a directory from before seeds were "
                    f"kept lacks it and ran with {DEFAULT_SEED}."),
    RunFile(name=STATUSES_FILE, required=False, json_schema=Statuses.model_json_schema(),
            content="How many of each tenant's requests received each response status, once the load ended; a "
                    f"repetition has it or {REFUSAL_FILE}."),
    RunFile(name=REFUSAL_FILE, required=False, json_schema=None,
            content="What a service said when it refused one of the rules, which ended the repetition."),
    RunFile(name=OBSERVATIONS, required=True, json_schema=ObservationRecord.model_json_schema(),
            content="The observation records of every service and process, one file each, one record per line."))


class RunOrigin(BaseModel):
    """What an executor's search runs share besides their directories: the workflow or experiment that ran them, the
    system at its revision, the SDK build and the system's build, and the environment they ran in."""

    model_config = FROZEN

    source: str
    system: str
    revision: str | None
    sdk_build: str
    build: dict[str, JsonValue]
    environment: str

    def context(self, deployment: dict[str, JsonValue]) -> RunContext:
        return RunContext(source=self.source, system=self.system, revision=self.revision,
                          sdk_build=self.sdk_build, build=self.build, deployment=deployment,
                          environment=self.environment)

    def search_run(self, directory: Path, root: Path, sequence: int, workload: NamedWorkload, group: str, index: int,
                   purpose: Purpose, phases: tuple[Phase, ...], requests: tuple[PathRequest, ...],
                   natural: NaturalPath | None = None) -> SearchRun:
        """A repetition's run directory as a search run: its rules, workload, deployment, seed, statuses or refusal,
        and its observation files summed, named by their paths relative to the root. A directory whose rule set is
        another repetition's, or that holds neither statuses nor a refusal, is an error."""
        label = f"{workload.name}.{group}.{index}"
        rules = RuleSet.model_validate_json((directory / RULES_FILE).read_bytes())
        if rules.experiment != label:
            raise ValueError(f"{directory} holds the rules of {rules.experiment}, not of {label}")
        statuses, refusal, seed = directory / STATUSES_FILE, directory / REFUSAL_FILE, directory / SEED_FILE
        if not statuses.exists() and not refusal.exists():
            raise ValueError(f"{directory} holds neither {STATUSES_FILE} nor {REFUSAL_FILE}: it never ended")
        files = sorted(directory.glob(OBSERVATIONS))
        return SearchRun(
            sequence=sequence, source=self.source,
            workload=workload.model_copy(update={"workload": PARAMETERS.validate_json(
                (directory / WORKLOAD_FILE).read_bytes())}),
            group=group, index=index, system=self.system, revision=self.revision, sdk_build=self.sdk_build,
            build=self.build, deployment=PARAMETERS.validate_json((directory / INSTRUMENTATION_FILE).read_bytes()),
            environment=self.environment, seed=int(seed.read_text()) if seed.exists() else DEFAULT_SEED,
            purpose=purpose, phases=phases, requests=requests, natural=natural,
            rules=rules.rules, tallies=tallies(read_records(files)),
            statuses=Statuses.model_validate_json(statuses.read_bytes()) if statuses.exists()
            else Statuses(tenants={}),
            refusal=refusal.read_text() if refusal.exists() else None,
            observations=tuple(str(path.relative_to(root)) for path in files))


class RepetitionLookup(BaseModel):
    model_config = FROZEN

    through: int
    recorded: str | None


def lookup_repetition(facts: Facts, origin: RunOrigin, request: RunRequest, deployment: dict[str, JsonValue],
                      index: int) -> RepetitionLookup:
    if not 0 <= index < request.repetitions:
        raise ValueError("the repetition index must be within the request")
    label = request.labels()[index]
    matches = [run for run in facts.standing_runs() if run.label == label and run.source == origin.source]
    if len(matches) > 1:
        raise ValueError(f"two search runs have the label {label}")
    through = facts.facts[-1].sequence if facts.facts else 0
    if not matches:
        return RepetitionLookup(through=through, recorded=None)
    run = matches[0]
    if ((run.system, run.revision, run.sdk_build, run.environment)
            != (origin.system, origin.revision, origin.sdk_build, origin.environment)
            or canonical(run.build) != canonical(origin.build)
            or canonical(run.deployment) != canonical(deployment)
            or canonical(run.workload.model_dump(mode="json")) != canonical(request.workload.model_dump(mode="json"))
            or run.seed != repetition_seed(label) or run.rules != request.ruleset(label).rules
            or run.natural != request.natural or run.phases != request.phases or run.requests != request.requests
            or (run.group != CONTROL_GROUP and run.purpose != request.purpose)):
        raise ValueError(f"the recorded search run {run.identity} has different execution inputs")
    return RepetitionLookup(through=through, recorded=run.identity)


def print_repetition_lookup() -> None:
    """Find a standing repetition with the requested execution inputs, or refuse a conflicting label.

    Repetitions belong to their source. A matching run is reused under its actual recorded identity;
    conflicting execution inputs of that same identity are refused.
    """
    parser = argparse.ArgumentParser(description=print_repetition_lookup.__doc__)
    parser.add_argument("facts", type=Path, help="The current fact file.")
    parser.add_argument("origin", type=Path, help="The proposed run origin.")
    parser.add_argument("request", type=Path, help="The planned run request.")
    parser.add_argument("deployment", type=Path, help="The deployment configuration the executor will use.")
    parser.add_argument("--index", type=int, required=True, help="The repetition's index in the request.")
    arguments = parser.parse_args()
    print(lookup_repetition(read_facts(arguments.facts), RunOrigin.model_validate_json(arguments.origin.read_bytes()),
        RunRequest.model_validate_json(arguments.request.read_bytes()),
        PARAMETERS.validate_json(arguments.deployment.read_bytes()), arguments.index).model_dump_json())


def point_inventory(facts: Facts, controls: tuple[str, ...], manifests: Path, configured: tuple[str, ...],
                    sequence: int) -> PointInventory:
    """The point inventory of the build the named control runs ran: the manifests of its rewriters, the points its
    deployment configures, and those runs, whose system, revision, SDK build and deployment it takes; control runs
    that disagree on them are an error."""
    runs = [run for run in facts.standing_runs() if run.group == CONTROL_GROUP]
    named = []
    for reference in controls:
        exact = [run for run in runs if run.identity == reference]
        matches = exact or [run for run in runs if run.label == reference]
        if len(matches) != 1:
            raise ValueError(f"control {reference} resolves to {len(matches)} runs; name its recorded identity")
        named.append(matches[0])
    if not named or any(run.context != named[0].context for run in named):
        raise ValueError(f"the control runs {controls} must share one execution context")
    first = named[0]
    candidate = PointInventory(sequence=sequence, system=first.system, revision=first.revision, sdk_build=first.sdk_build,
                          deployment=first.deployment, controls=tuple(run.identity for run in named), manifests=read_manifests(manifests),
                          configured=configured)
    for inventory in facts.inventories():
        if (inventory.system, inventory.revision, inventory.sdk_build, inventory.deployment) != (
                candidate.system, candidate.revision, candidate.sdk_build, candidate.deployment):
            continue
        if tuple(run.identity for run in facts.inventory_controls(inventory)) == candidate.controls:
            if (inventory.manifests, inventory.configured) != (candidate.manifests, candidate.configured):
                raise ValueError(f"inventory {inventory.identity} already records different points for these controls")
            return inventory.model_copy(update={"sequence": sequence})
    return candidate


def print_search_run() -> None:
    """Print, as one line of JSON, the search run fact of one repetition of a run request, read from the run
    directory its executor left."""
    parser = argparse.ArgumentParser(description=print_search_run.__doc__)
    parser.add_argument("origin", type=Path, help="The run origin, a JSON object.")
    parser.add_argument("request", type=Path, help="The run request, a JSON object, as the plan gave it.")
    parser.add_argument("directory", type=Path, help="The repetition's run directory.")
    parser.add_argument("--index", type=int, required=True, help="The repetition's index in the request.")
    parser.add_argument("--sequence", type=int, required=True, help="The fact's number.")
    parser.add_argument("--root", type=Path, required=True,
                        help="The directory the observation files are named relative to, which holds the run one.")
    arguments = parser.parse_args()
    request = RunRequest.model_validate_json(arguments.request.read_bytes())
    run = RunOrigin.model_validate_json(arguments.origin.read_bytes()).search_run(
        arguments.directory, arguments.root, arguments.sequence, request.workload, request.group, arguments.index,
        request.purpose, request.phases, request.requests, request.natural)
    print(FACT.dump_json(run).decode())


def print_point_inventory() -> None:
    """Print, as one line of JSON, the point inventory fact a plan step asks for, from the control runs it names in a
    fact file, the manifests of a build and the points its deployment configures."""
    parser = argparse.ArgumentParser(description=print_point_inventory.__doc__)
    parser.add_argument("facts", type=Path, help="A fact file: one fact per line, in sequence order.")
    parser.add_argument("manifests", type=Path, help="The directory of the build's manifests.")
    parser.add_argument("--control", action="append", required=True, help="A recorded control identity; a legacy label must be unique.")
    parser.add_argument("--configured", action="append", default=[], help="A point the deployment configures.")
    parser.add_argument("--sequence", type=int, required=True, help="The fact's number.")
    arguments = parser.parse_args()
    print(FACT.dump_json(point_inventory(read_facts(arguments.facts), tuple(arguments.control), arguments.manifests,
                                         tuple(arguments.configured), arguments.sequence)).decode())


def print_origin_schema() -> None:
    print(json.dumps(RunOrigin.model_json_schema(), indent=2))


def print_run_directory() -> None:
    """Print, as JSON, the files of a run directory, each with the JSON Schema of its content."""
    print(TypeAdapter(tuple[RunFile, ...]).dump_json(RUN_FILES, indent=2).decode())
