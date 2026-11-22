import os
import subprocess
import time
from concurrent.futures import Future, ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
from typing import Final

from faultpoint.observations import ObservationRecord, read_records
from faultpoint.rules import RuleSet
from faultpoint.tools.kinds import KindTable
from faultsearch.catalog import FROZEN, Fault
from faultsearch.chains import Chain
from faultsearch.counterfactual import (DEFAULT_SEED, ControlRecord, Group, Leak, NamedWorkload, Repetitions, Scenarios,
                                        Statuses, TreatmentRecord, Workload, control_labels, pack)
from faultsearch.validation import Selection, Validation, Validations, hop_checks, merged_workload
from pydantic import BaseModel, Field, JsonValue

from faultsearch_local.store import CONTROLS, LEAKS, TREATMENTS, Store
from faultsearch_local.systems import REFUSAL_FILE, SEED_FILE, STATUSES_FILE, System

LOAD_POLL_S: Final = 2.0
"""How often a repetition held back by the host's load checks it again."""

type Job = tuple[str, Workload, RuleSet]
"""A repetition to run: its label, its workload and its rules."""
type Running = list[tuple[str, Future[Statuses]]]
"""Repetitions submitted, by label."""


class RunSettings(BaseModel):
    model_config = FROZEN

    sdk: Path
    commit: str
    repetitions: int = Field(ge=2)
    alpha: float
    min_mean_increase: float
    workers: int = Field(ge=1)
    pack_tenants: bool = True
    """Whether faults share repetitions in different tenants; off when upstream components are observed, since no
    tenant scope separates their observations."""
    system: str = "shop"
    """The system the experiment explores, by name."""
    instrumentation: dict[str, JsonValue]
    """What of faultpoint runs and what the kernel agent observes, the same in every repetition, as the system's
    deployment reads it."""


def treatment_record(store: Store, fault: Fault, workload: str) -> TreatmentRecord:
    return store.load(TreatmentRecord, TREATMENTS, workload, f"{fault.digest}.json")


def repetition_seed(label: str) -> int:
    """The FAULTPOINT_SEED of a repetition, from its label, so that the repetitions of one group draw their rules'
    chances anew and a repetition run again draws the same."""
    return int(sha256(label.encode()).hexdigest()[:15], 16)


def finish(running: Running) -> None:
    """Wait for repetitions to end, showing each one's statuses, and raise what failed in one."""
    for label, future in running:
        print(label, future.result().tenants, flush=True)


class Runner(Repetitions):
    """Runs repetitions side by side and turns them into control and treatment records, keeping every record so that
    a repeated request reads it instead of running again."""

    def __init__(self, store: Store, settings: RunSettings, system: System, max_load: float) -> None:
        super().__init__(settings.alpha, settings.min_mean_increase)
        self.store = store
        self.settings = settings
        self.system = system
        self.max_load = max_load
        """The host's 1-minute load above which no new repetition starts while others still run."""
        self.kinds = KindTable.installed()
        self.cache: dict[str, list[ObservationRecord]] = {}

    def wait_for_load(self, started: list[Future[Statuses]]) -> None:
        """Wait, while a repetition still runs, until the host's load falls under the limit, so that a loaded host
        does not slow the repetitions whose timing the faults depend on."""
        while any(not future.done() for future in started) and os.getloadavg()[0] > self.max_load:
            time.sleep(LOAD_POLL_S)

    def observations(self, label: str) -> list[ObservationRecord]:
        if label not in self.cache:
            self.cache[label] = read_records(sorted(self.store.repetition(label).glob("*.jsonl")))
        return self.cache[label]

    def statuses(self, label: str) -> Statuses:
        return Statuses.model_validate_json((self.store.repetition(label) / STATUSES_FILE).read_text())

    def seed(self, label: str) -> int:
        """The FAULTPOINT_SEED a repetition ran with; one from before repetitions had their own ran with the SDKs'
        default, 0."""
        path = self.store.repetition(label) / SEED_FILE
        return int(path.read_text()) if path.exists() else DEFAULT_SEED

    def refusal(self, label: str) -> str | None:
        path = self.store.repetition(label) / REFUSAL_FILE
        return path.read_text() if path.exists() else None

    def pending(self, jobs: list[Job]) -> list[Job]:
        """The repetitions not run before, every rule of which the kind table allows."""
        pending = [job for job in jobs if not (self.store.repetition(job[0]) / STATUSES_FILE).exists()
                   and not (self.store.repetition(job[0]) / REFUSAL_FILE).exists()]
        for _, _, ruleset in pending:
            violations = self.kinds.violations(ruleset)
            if violations:
                raise ValueError(f"{ruleset.experiment}: {violations}")
        return pending

    def start(self, pool: ThreadPoolExecutor, jobs: list[Job], started: list[Future[Statuses]]) -> Running:
        """Submit repetitions, each once the host's load allows, adding them to those started."""
        running = []
        for job in jobs:
            self.wait_for_load(started)
            future = pool.submit(self.repetition, job)
            started.append(future)
            running.append((job[0], future))
        return running

    def repeat(self, jobs: list[Job]) -> None:
        """Run the repetitions not run before."""
        with ThreadPoolExecutor(self.settings.workers) as pool:
            finish(self.start(pool, self.pending(jobs), []))

    def rerecord(self, pairs: list[tuple[Fault, NamedWorkload]]) -> None:
        """Record again, from the repetitions they ran, the treatments of faults in workloads, which runs only the
        repetitions missing, so that records gain what a newer record keeps."""
        self.run_groups([Group(workload=workload, faults=(fault,)) for fault, workload in pairs])

    def repetition(self, job: Job) -> Statuses:
        """One repetition; a service refusing a rule ends it, which is recorded so that the fault counts as never
        exercised instead of stopping the experiment."""
        label, workload, ruleset = job
        directory = self.store.repetition(label)
        try:
            return self.system.repetition(directory, workload, ruleset.model_dump(mode="json"), self.settings.sdk,
                                          self.settings.instrumentation, repetition_seed(label))
        except subprocess.CalledProcessError:
            reason = self.system.refusal(directory)
            if reason is None:
                raise
            (directory / REFUSAL_FILE).write_text(reason)
            return Statuses(tenants={})

    def controls(self, workloads: list[NamedWorkload]) -> list[ControlRecord]:
        missing = [workload for workload in workloads if not self.store.has(CONTROLS, f"{workload.name}.json")]
        self.repeat([(label, workload.workload, RuleSet(experiment=label)) for workload in missing
                     for label in control_labels(workload, self.settings.repetitions)])
        for workload in missing:
            labels = control_labels(workload, self.settings.repetitions)
            self.store.save(ControlRecord(workload=workload, labels=tuple(labels),
                                          statuses=tuple(self.statuses(label) for label in labels)),
                            CONTROLS, f"{workload.name}.json")
        return [self.store.load(ControlRecord, CONTROLS, f"{workload.name}.json") for workload in workloads]

    def settle(self, group: Group, running: Running) -> Group | None:
        """Once a group's repetitions ended, keep its faults' records, or, for a packed group whose untreated tenant
        changed, the leak, returning the group so that its faults run again alone."""
        finish(running)
        records = self.group_records(group, self.controls([group.workload])[0].labels,
                                     group.labels(self.settings.repetitions))
        if len(group.faults) > 1 and records[0].leakage:
            self.store.save(Leak(group=group, leakage=records[0].leakage), LEAKS, group.workload.name,
                            f"{group.digest}.json")
            return group
        for record in records:
            self.store.save(record, TREATMENTS, record.workload, f"{record.fault.digest}.json")
        return None

    def run_groups(self, groups: list[Group]) -> list[Group]:
        """Run groups and keep every group's records as soon as its repetitions end, so that a run stopped or failing
        midway keeps the groups it finished; returns the packed groups whose untreated tenant changed, whose faults
        must run again alone."""
        self.controls(list({group.workload.name: group.workload for group in groups}.values()))
        jobs = [self.pending([(label, group.workload.workload, group.ruleset(label))
                              for label in group.labels(self.settings.repetitions)]) for group in groups]
        leaking: list[Group] = []
        unsettled: list[tuple[Group, Running]] = []
        started: list[Future[Statuses]] = []
        with ThreadPoolExecutor(self.settings.workers) as pool:
            for group, group_jobs in zip(groups, jobs, strict=True):
                unsettled.append((group, self.start(pool, group_jobs, started)))
                ended = [all(future.done() for _, future in running) for _, running in unsettled]
                leaking += [leak for (waiting, running), done in zip(unsettled, ended, strict=True)
                            if done and (leak := self.settle(waiting, running)) is not None]
                unsettled = [entry for entry, done in zip(unsettled, ended, strict=True) if not done]
            leaking += [leak for waiting, running in unsettled if (leak := self.settle(waiting, running)) is not None]
        return leaking

    def recorded(self, pairs: list[tuple[Fault, NamedWorkload]]) -> list[TreatmentRecord]:
        return [treatment_record(self.store, fault, workload.name) for fault, workload in pairs]

    def missing(self, pairs: list[tuple[Fault, NamedWorkload]]) -> list[tuple[Fault, NamedWorkload]]:
        """The distinct pairs without a record, since chains that share a first fault and a workload share its run."""
        distinct = {(workload.name, fault.digest): (fault, workload) for fault, workload in pairs}
        return [(fault, workload) for (name, digest), (fault, workload) in distinct.items()
                if not self.store.has(TREATMENTS, name, f"{digest}.json")]

    def treatments(self, pairs: list[tuple[Fault, NamedWorkload]]) -> list[TreatmentRecord]:
        """The records of faults in workloads, packing faults that do not delay into shared repetitions when the
        settings allow it."""
        if not self.settings.pack_tenants:
            return self.isolated_treatments(pairs)
        leaking = self.run_groups(pack(self.missing(pairs)))
        self.run_groups([Group(workload=group.workload, faults=(fault,)) for group in leaking for fault in group.faults])
        return self.recorded(pairs)

    def isolated_treatments(self, pairs: list[tuple[Fault, NamedWorkload]]) -> list[TreatmentRecord]:
        """The records of faults in workloads, each fault in repetitions of its own."""
        self.run_groups([Group(workload=workload, faults=(fault,)) for fault, workload in self.missing(pairs)])
        return self.recorded(pairs)

    def validate(self, chains: list[tuple[Chain, Selection]], scenarios: Scenarios,
                 min_count_increase: float) -> Validations:
        """Every chain checked end to end: its first fault alone in the workload its conditions merge into."""
        workloads = [merged_workload(chain.condition, scenarios) for chain, _ in chains]
        records = self.isolated_treatments([(chain.hops[0].cause, workload)
                                            for (chain, _), workload in zip(chains, workloads, strict=True)])
        return Validations(validations=tuple(
            Validation(chain=chain, selection=selection, workload=workload, record=record,
                       hops=hop_checks(chain, record, min_count_increase))
            for (chain, selection), workload, record in zip(chains, workloads, records, strict=True)))
