from pathlib import Path
from typing import Final

from faultpoint.observations import read_records
from faultpoint.rules import RuleSet
from faultsearch.allocation import Allocation, Phase, Strategy
from faultsearch.catalog import read_manifests
from faultsearch.counterfactual import DEFAULT_SEED, ControlRecord, NamedWorkload, Scenarios, Statuses, TreatmentRecord
from faultsearch.edges import EffectMap
from faultsearch.facts import (CONTROL_GROUP, FACT, Fact, Facts, LoadVariants, PathRequest, PointInventory, Purpose,
                               SearchRun, SystemTopology, tallies)
from faultsearch.validation import VALIDATION_PREFIX, Selection, Validations
from pydantic import BaseModel, JsonValue, TypeAdapter

from faultsearch_local.runner import RunSettings
from faultsearch_local.store import (CONTROLS, EFFECTS_INPUT, INPUTS, REPETITIONS, RUN_SETTINGS, SCENARIOS_INPUT,
                                     TREATMENTS, VALIDATIONS, Store, allocation_file)
from faultsearch_local.systems import REFUSAL_FILE, SEED_FILE, STATUSES_FILE, System

FACTS: Final = "facts.jsonl"
"""The local fact directory's file: one fact per line, in sequence order."""
LOCAL_ENVIRONMENT: Final = "local-docker"
"""Where the local executor runs repetitions: its own containers and network namespaces on this host."""
RULES_FILE: Final = "rules.json"
WORKLOAD_FILE: Final = "workload.json"
INSTRUMENTATION_FILE: Final = "instrumentation.json"


def write_facts(path: Path, facts: Facts) -> None:
    path.write_text("".join(f"{FACT.dump_json(fact).decode()}\n" for fact in facts.facts), encoding="utf-8")


def read_facts(path: Path) -> Facts:
    return Facts(facts=tuple(FACT.validate_json(line) for line in path.read_text(encoding="utf-8").splitlines()))


class Imported(BaseModel):
    """An experiment directory's facts, and the repetition directories they leave out because no record of the
    experiment refers to them."""

    facts: Facts
    unreferenced: tuple[str, ...]
    """Those that ran to their end."""
    unfinished: tuple[str, ...]
    """Those without statuses, which never ran to their end."""


class RunImport:
    """The conversion of one experiment directory's repetitions into search runs, numbered in the order they are
    taken."""

    def __init__(self, store: Store, system: System, settings: RunSettings) -> None:
        self.store = store
        self.system = system
        self.settings = settings
        self.facts: list[Fact] = []
        self.taken: set[str] = set()

    def run(self, label: str, workload: NamedWorkload, group: str, index: int, purpose: Purpose,
            phases: tuple[Phase, ...], requests: tuple[PathRequest, ...]) -> None:
        """One repetition directory as a search run, unless taken before."""
        if label in self.taken:
            return
        self.taken.add(label)
        directory = self.store.repetition(label)
        files = sorted(directory.glob("*.jsonl"))
        seed = directory / SEED_FILE
        refusal = directory / REFUSAL_FILE
        deployment = TypeAdapter(dict[str, JsonValue]).validate_json((directory / INSTRUMENTATION_FILE).read_bytes())
        self.facts.append(SearchRun(
            sequence=len(self.facts) + 1, source=self.store.root.name,
            workload=workload.model_copy(update={"workload": TypeAdapter(dict[str, JsonValue]).validate_json(
                (directory / WORKLOAD_FILE).read_bytes())}),
            group=group, index=index, system=self.system.name, revision=None, sdk_build=self.settings.commit,
            build={"system": self.system.name}, deployment=deployment, environment=LOCAL_ENVIRONMENT,
            seed=int(seed.read_text()) if seed.exists() else DEFAULT_SEED, purpose=purpose, phases=phases,
            requests=requests, rules=RuleSet.model_validate_json((directory / RULES_FILE).read_bytes()).rules,
            tallies=tallies(read_records(files)),
            statuses=Statuses.model_validate_json((directory / STATUSES_FILE).read_bytes())
            if (directory / STATUSES_FILE).exists() else Statuses(tenants={}),
            refusal=refusal.read_text() if refusal.exists() else None,
            observations=tuple(str(path.relative_to(self.store.root)) for path in files)))

    def controls(self, control: ControlRecord, purpose: Purpose) -> None:
        for index, label in enumerate(control.labels):
            self.run(label, control.workload, CONTROL_GROUP, index, purpose, (), ())

    def treatments(self, record: TreatmentRecord, workload: NamedWorkload, purpose: Purpose,
                   phases: dict[str, Phase], requests: tuple[PathRequest, ...]) -> None:
        """The repetitions of a treatment record, with the phase of every fault their rules inject, by the id of the
        fault's own rule."""
        for index, label in enumerate(record.labels):
            rules = RuleSet.model_validate_json((self.store.repetition(label) / RULES_FILE).read_bytes()).rules
            self.run(label, workload, label.split(".")[-2], index, purpose,
                     tuple(phases[rule.id] for rule in rules if rule.id in phases), requests)


def experiment_facts(store: Store, system: System) -> Imported:
    """An experiment directory as facts: the system's topology and load variants, the control runs of every load
    variant and the point inventory they complete, the runs of every assignment of the phased allocation in its order,
    the controls of the merged workloads and the runs of the validations. Only the repetitions a record of the
    experiment refers to are taken."""
    settings = store.load(RunSettings, RUN_SETTINGS)
    scenarios = store.load(Scenarios, INPUTS, SCENARIOS_INPUT)
    effects = store.load(EffectMap, INPUTS, EFFECTS_INPUT)
    taking = RunImport(store, system, settings)
    taking.facts.append(SystemTopology(sequence=1, system=system.name, upstream=system.upstream,
                                       entry_service=system.entry_service, terminal_outcomes=effects.terminal_outcomes,
                                       ports=system.ports, targets=system.targets))
    taking.facts.append(LoadVariants(sequence=2, system=system.name, scenarios=scenarios))
    controls = {path.stem: store.load(ControlRecord, CONTROLS, path.name)
                for path in sorted(store.path(CONTROLS).glob("*.json"))}
    variants = [scenario.name for scenario in scenarios.scenarios]
    for name in variants:
        taking.controls(controls[name], Purpose.EDGE)
    taking.facts.append(PointInventory(sequence=len(taking.facts) + 1, system=system.name, revision=None,
                                       sdk_build=settings.commit, deployment=settings.instrumentation,
                                       controls=tuple(label for name in variants for label in controls[name].labels),
                                       manifests=read_manifests(system.manifests), configured=system.configured))
    allocation = store.load(Allocation, allocation_file(Strategy.PHASED))
    phases: dict[str, dict[str, Phase]] = {name: {} for name in variants}
    for assignment in allocation.assignments:
        phases[assignment.scenario][assignment.fault.digest] = assignment.phase
    for assignment in allocation.assignments:
        record = store.load(TreatmentRecord, TREATMENTS, assignment.scenario, f"{assignment.fault.digest}.json")
        taking.treatments(record, NamedWorkload(name=assignment.scenario, workload=scenarios.workload(
            assignment.scenario)), Purpose.EDGE, phases[assignment.scenario], ())
    for name, control in controls.items():
        if name.startswith(VALIDATION_PREFIX):
            taking.controls(control, Purpose.PATH)
    validations = store.load(Validations, VALIDATIONS).validations if store.has(VALIDATIONS) else ()
    requests: dict[tuple[str, ...], list[PathRequest]] = {}
    for validation in validations:
        if validation.selection != Selection.ADJUDICATED:
            requests.setdefault(validation.record.labels, []).append(
                PathRequest(chain=validation.chain.key, selection=validation.selection))
    for validation in validations:
        taking.treatments(validation.record, validation.workload, Purpose.PATH, {},
                          tuple(requests.get(validation.record.labels, ())))
    present = sorted(path.name for path in store.path(REPETITIONS).iterdir())
    left = [label for label in present if label not in taking.taken]
    return Imported(facts=Facts(facts=tuple(taking.facts)),
                    unreferenced=tuple(label for label in left if (store.repetition(label) / STATUSES_FILE).exists()),
                    unfinished=tuple(label for label in left if not (store.repetition(label) / STATUSES_FILE).exists()))
