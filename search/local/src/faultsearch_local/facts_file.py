from pathlib import Path
from typing import Final

from faultpoint.observations import read_records
from faultpoint.rules import RuleSet
from faultsearch.allocation import Phase
from faultsearch.counterfactual import DEFAULT_SEED, NamedWorkload, Statuses
from faultsearch.facts import FACT, Fact, FactList, PathRequest, Purpose, SearchRun, read_facts, tallies
from pydantic import JsonValue, TypeAdapter

from faultsearch_local.store import Store
from faultsearch_local.systems import REFUSAL_FILE, SEED_FILE, STATUSES_FILE

LOCAL_ENVIRONMENT: Final = "local-docker"
"""Where the local executor runs repetitions: its own containers and network namespaces on this host."""
RULES_FILE: Final = "rules.json"
WORKLOAD_FILE: Final = "workload.json"
INSTRUMENTATION_FILE: Final = "instrumentation.json"
PARAMETERS: Final = TypeAdapter(dict[str, JsonValue])


class FactLog(FactList):
    """An experiment's facts.jsonl, read once and then appended to, line by line."""

    def __init__(self, path: Path) -> None:
        super().__init__(list(read_facts(path).facts) if path.exists() else [])
        self.path = path

    def append(self, fact: Fact) -> None:
        super().append(fact)
        with self.path.open("a", encoding="utf-8") as lines:
            lines.write(f"{FACT.dump_json(fact).decode()}\n")


class RunOrigin:
    """Where a repetition directory's search run comes from: the experiment, the system, its build and the
    request it answers."""

    def __init__(self, store: Store, system: str, sdk_build: str) -> None:
        self.store = store
        self.system = system
        self.sdk_build = sdk_build

    def search_run(self, label: str, sequence: int, workload: NamedWorkload, group: str, index: int, purpose: Purpose,
                   phases: tuple[Phase, ...], requests: tuple[PathRequest, ...]) -> SearchRun:
        """A repetition directory as a search run: its rules, workload, deployment, seed, statuses or refusal, and its
        observation files summed."""
        directory = self.store.repetition(label)
        files = sorted(directory.glob("*.jsonl"))
        seed = directory / SEED_FILE
        refusal = directory / REFUSAL_FILE
        return SearchRun(
            sequence=sequence, source=self.store.root.name,
            workload=workload.model_copy(update={"workload": PARAMETERS.validate_json(
                (directory / WORKLOAD_FILE).read_bytes())}),
            group=group, index=index, system=self.system, revision=None, sdk_build=self.sdk_build,
            build={"system": self.system},
            deployment=PARAMETERS.validate_json((directory / INSTRUMENTATION_FILE).read_bytes()),
            environment=LOCAL_ENVIRONMENT, seed=int(seed.read_text()) if seed.exists() else DEFAULT_SEED,
            purpose=purpose, phases=phases, requests=requests,
            rules=RuleSet.model_validate_json((directory / RULES_FILE).read_bytes()).rules,
            tallies=tallies(read_records(files)),
            statuses=Statuses.model_validate_json((directory / STATUSES_FILE).read_bytes())
            if (directory / STATUSES_FILE).exists() else Statuses(tenants={}),
            refusal=refusal.read_text() if refusal.exists() else None,
            observations=tuple(str(path.relative_to(self.store.root)) for path in files))
