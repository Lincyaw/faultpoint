from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path

from faultpoint.observations import ObservationRecord, read_records
from faultpoint.rules import Rule, RuleSet
from faultpoint.tools.analysis import Comparison, Effect, Selection, compare
from faultpoint.tools.kinds import KindTable
from pydantic import BaseModel, Field
from shop.deployment import SCOPE_KEY, STATUSES_FILE, Statuses, repetition
from shop.workload import Workload

from faultsearch.catalog import FROZEN, Fault
from faultsearch.store import CONTROLS, LEAKS, TREATMENTS, Store


class RunSettings(BaseModel):
    model_config = FROZEN

    sdk: Path
    commit: str
    repetitions: int = Field(ge=2)
    alpha: float
    min_mean_increase: float
    workers: int = Field(ge=1)


class NamedWorkload(BaseModel):
    model_config = FROZEN

    name: str
    workload: Workload


class ControlRecord(BaseModel):
    model_config = FROZEN

    workload: NamedWorkload
    labels: tuple[str, ...]
    statuses: tuple[Statuses, ...]


class TreatmentRecord(BaseModel):
    """One fault injected in one tenant of a workload, compared with that tenant in the workload's controls."""

    model_config = FROZEN

    fault: Fault
    workload: str
    tenant: str
    labels: tuple[str, ...]
    packed_with: tuple[str, ...]
    """The faults injected in other tenants of the same repetitions."""
    injected: tuple[int, ...]
    statuses: tuple[dict[int, int], ...]
    effects: tuple[Effect, ...]
    leakage: dict[str, tuple[Effect, ...]]
    """The effects the untreated tenants of the same repetitions showed, by tenant."""

    @property
    def exercised(self) -> bool:
        return all(self.injected)


class Group(BaseModel):
    """Faults that share the repetitions of one workload, each in a tenant of its own, and every treated tenant
    followed by an untreated one in the interleaved load, so that a fault reaching beyond its tenant shows there."""

    model_config = FROZEN

    workload: NamedWorkload
    faults: tuple[Fault, ...] = Field(min_length=1)

    @property
    def digest(self) -> str:
        placed = zip(self.tenants(), self.faults, strict=True)
        return sha256("\n".join(f"{tenant} {fault.key}" for tenant, fault in placed).encode()).hexdigest()[:12]

    def labels(self, repetitions: int) -> list[str]:
        return [f"{self.workload.name}.{self.digest}.{index}" for index in range(repetitions)]

    def tenants(self) -> list[str]:
        """Every other tenant, since the load interleaves the tenants and a fault can break the request after its own."""
        return self.workload.workload.tenant_names()[::2][:len(self.faults)]

    def untreated(self) -> list[str]:
        return [tenant for tenant in self.workload.workload.tenant_names() if tenant not in self.tenants()]

    def ruleset(self, label: str) -> RuleSet:
        return RuleSet(experiment=label, rules=tuple(
            Rule(id=fault.digest, point=fault.point, action=fault.action, scope={SCOPE_KEY: tenant})
            for fault, tenant in zip(self.faults, self.tenants(), strict=True)))


class Leak(BaseModel):
    """A packed group whose untreated tenants changed, so that its faults ran again alone."""

    model_config = FROZEN

    group: Group
    leakage: dict[str, tuple[Effect, ...]]


def treatment_record(store: Store, fault: Fault, workload: str) -> TreatmentRecord:
    return store.load(TreatmentRecord, TREATMENTS, workload, f"{fault.digest}.json")


def control_labels(workload: NamedWorkload, repetitions: int) -> list[str]:
    return [f"{workload.name}.control.{index}" for index in range(repetitions)]


def pack(pairs: list[tuple[Fault, NamedWorkload]]) -> list[Group]:
    """Groups of faults of one workload that share repetitions; a delay runs alone, since it acts through what the
    tenants share (a connection, a lock, an event loop, the sequential load) and so leaks by construction."""
    by_workload: dict[str, list[Fault]] = defaultdict(list)
    workloads = {workload.name: workload for _, workload in pairs}
    for fault, workload in pairs:
        by_workload[workload.name].append(fault)
    groups = []
    for name, faults in by_workload.items():
        workload = workloads[name]
        capacity = workload.workload.tenants // 2
        shared = [fault for fault in faults if not fault.delays]
        groups += [Group(workload=workload, faults=(fault,)) for fault in faults if fault.delays]
        groups += [Group(workload=workload, faults=tuple(shared[start:start + capacity]))
                   for start in range(0, len(shared), capacity)]
    return groups


class Runner:
    """Runs repetitions side by side and turns them into control and treatment records, keeping every record so that
    a repeated request reads it instead of running again."""

    def __init__(self, store: Store, settings: RunSettings) -> None:
        self.store = store
        self.settings = settings
        self.kinds = KindTable.installed()
        self.cache: dict[str, list[ObservationRecord]] = {}

    def observations(self, label: str) -> list[ObservationRecord]:
        if label not in self.cache:
            self.cache[label] = read_records(sorted(self.store.repetition(label).glob("*.jsonl")))
        return self.cache[label]

    def statuses(self, label: str) -> Statuses:
        return Statuses.model_validate_json((self.store.repetition(label) / STATUSES_FILE).read_text())

    def repeat(self, jobs: list[tuple[str, Workload, RuleSet]]) -> None:
        """Run the repetitions not run before."""
        pending = [job for job in jobs if not (self.store.repetition(job[0]) / STATUSES_FILE).exists()]
        for _, _, ruleset in pending:
            violations = self.kinds.violations(ruleset)
            if violations:
                raise ValueError(f"{ruleset.experiment}: {violations}")
        with ThreadPoolExecutor(self.settings.workers) as pool:
            for label, statuses in zip([job[0] for job in pending], pool.map(self.repetition, pending), strict=True):
                print(label, statuses.tenants, flush=True)

    def repetition(self, job: tuple[str, Workload, RuleSet]) -> Statuses:
        label, workload, ruleset = job
        return repetition(self.store.repetition(label), workload, ruleset.model_dump(mode="json"), self.settings.sdk)

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

    def comparison(self, control: tuple[str, ...], treatment: list[str], tenant: str) -> Comparison:
        records = [record for label in (*control, *treatment) for record in self.observations(label)]
        return compare(records, [Selection(experiment=label, scope=tenant) for label in control],
                       [Selection(experiment=label, scope=tenant) for label in treatment],
                       self.settings.alpha, self.settings.min_mean_increase)

    def group_records(self, group: Group) -> list[TreatmentRecord]:
        control = self.controls([group.workload])[0].labels
        labels = group.labels(self.settings.repetitions)
        leakage = {tenant: effects for tenant in group.untreated()
                   if (effects := self.comparison(control, labels, tenant).effects)}
        records = []
        for fault, tenant in zip(group.faults, group.tenants(), strict=True):
            comparison = self.comparison(control, labels, tenant)
            injected = [sum(injection.counts[index] for injection in comparison.injections
                            if injection.rule == fault.digest) for index in range(len(labels))]
            records.append(TreatmentRecord(
                fault=fault, workload=group.workload.name, tenant=tenant, labels=tuple(labels),
                packed_with=tuple(other.key for other in group.faults if other != fault), injected=tuple(injected),
                statuses=tuple(self.statuses(label).tenants[tenant] for label in labels),
                effects=comparison.effects, leakage=leakage))
        return records

    def run_groups(self, groups: list[Group]) -> list[Group]:
        """Run groups and keep their faults' records; returns the packed groups whose untreated tenant changed, whose
        faults must run again alone."""
        self.controls(list({group.workload.name: group.workload for group in groups}.values()))
        self.repeat([(label, group.workload.workload, group.ruleset(label)) for group in groups
                     for label in group.labels(self.settings.repetitions)])
        leaking = []
        for group in groups:
            records = self.group_records(group)
            if len(group.faults) > 1 and records[0].leakage:
                self.store.save(Leak(group=group, leakage=records[0].leakage), LEAKS, group.workload.name,
                                f"{group.digest}.json")
                leaking.append(group)
                continue
            for record in records:
                self.store.save(record, TREATMENTS, record.workload, f"{record.fault.digest}.json")
        return leaking

    def recorded(self, pairs: list[tuple[Fault, NamedWorkload]]) -> list[TreatmentRecord]:
        return [treatment_record(self.store, fault, workload.name) for fault, workload in pairs]

    def missing(self, pairs: list[tuple[Fault, NamedWorkload]]) -> list[tuple[Fault, NamedWorkload]]:
        """The distinct pairs without a record, since chains that share a first fault and a workload share its run."""
        distinct = {(workload.name, fault.digest): (fault, workload) for fault, workload in pairs}
        return [(fault, workload) for (name, digest), (fault, workload) in distinct.items()
                if not self.store.has(TREATMENTS, name, f"{digest}.json")]

    def treatments(self, pairs: list[tuple[Fault, NamedWorkload]]) -> list[TreatmentRecord]:
        """The records of faults in workloads, packing faults that do not delay into shared repetitions."""
        leaking = self.run_groups(pack(self.missing(pairs)))
        self.run_groups([Group(workload=group.workload, faults=(fault,)) for group in leaking for fault in group.faults])
        return self.recorded(pairs)

    def isolated_treatments(self, pairs: list[tuple[Fault, NamedWorkload]]) -> list[TreatmentRecord]:
        """The records of faults in workloads, each fault in repetitions of its own."""
        self.run_groups([Group(workload=workload, faults=(fault,)) for fault, workload in self.missing(pairs)])
        return self.recorded(pairs)
