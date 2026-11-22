from abc import ABC, abstractmethod
from collections import defaultdict
from hashlib import sha256
from pathlib import Path
from string import ascii_lowercase
from typing import Final, Self

from faultpoint.observations import ObservationRecord
from faultpoint.rules import Rule, RuleSet, Trigger
from faultpoint.tools.analysis import Comparison, Effect, Metric, Selection, compare
from pydantic import BaseModel, Field, JsonValue

from faultsearch.catalog import BOUNDARY_KINDS, FROZEN, Fault, point_kind

UNSCOPED: Final = ""
"""The scope of observations no request baggage reached, such as the kernel's."""
DEFAULT_SEED: Final = 0
"""The seed every SDK draws with when FAULTPOINT_SEED is not set."""
TENANTS: Final = "tenants"
"""The workload parameter every system has: how many tenants, named a, b, c and on, send requests."""
SCOPE_KEY: Final = "fp.scope"
"""The baggage key a tenant's requests carry its name in, which rules scope by."""

type Workload = dict[str, JsonValue]
"""A workload's parameters, as the system that runs it validates them."""


def tenant_names(workload: Workload) -> list[str]:
    tenants = workload[TENANTS]
    if not isinstance(tenants, int):
        raise TypeError(f"the workload parameter {TENANTS} is {tenants!r}, not a number of tenants")
    return list(ascii_lowercase[:tenants])


class Scenario(BaseModel):
    """A business situation that changes a system's baseline workload."""

    model_config = FROZEN

    name: str = Field(pattern=r"^[a-z0-9-]+$")
    reason: str
    changes: Workload


class Scenarios(BaseModel):
    model_config = FROZEN

    baseline: Workload
    scenarios: tuple[Scenario, ...]

    @classmethod
    def read(cls, path: Path) -> Self:
        return cls.model_validate_json(path.read_text(encoding="utf-8"))

    def named(self, name: str) -> Scenario:
        return {scenario.name: scenario for scenario in self.scenarios}[name]

    def workload(self, name: str) -> Workload:
        return {**self.baseline, **self.named(name).changes}


class NamedWorkload(BaseModel):
    model_config = FROZEN

    name: str
    workload: Workload


class Statuses(BaseModel):
    """How many of each tenant's requests received each response status."""

    model_config = FROZEN

    tenants: dict[str, dict[int, int]]


class ControlRecord(BaseModel):
    model_config = FROZEN

    workload: NamedWorkload
    labels: tuple[str, ...]
    statuses: tuple[Statuses, ...]


class Load(BaseModel):
    """What one point and outcome did in a set of repetitions."""

    model_config = FROZEN

    count: float
    """The executions per repetition."""
    mean: float
    """The mean of the executions' totals, the response time at a boundary point."""


def effects_elapsed(records: list[ObservationRecord], labels: list[str], scopes: set[str],
                    effects: tuple[Effect, ...]) -> dict[str, float]:
    """The mean elapsed time of the natural executions behind each count effect, in the repetitions and scopes the
    effect was compared in."""
    sums: dict[tuple[str, str, tuple[tuple[str, str], ...]], list[float]] = defaultdict(lambda: [0.0, 0.0])
    for record in records:
        if record.rule is None and record.experiment in labels and record.scope in scopes:
            totals = sums[(record.point, record.outcome, tuple(sorted(record.detail.items())))]
            totals[0] += record.elapsed
            totals[1] += record.count
    elapsed = {}
    for effect in effects:
        totals = sums.get((effect.point, effect.outcome, tuple(sorted(effect.detail.items()))))
        if effect.metric == Metric.COUNT and totals is not None and totals[1]:
            elapsed[EffectKey.of(effect).key] = totals[0] / totals[1]
    return elapsed


def effects_rates(records: list[ObservationRecord], labels: list[str], scopes: set[str],
                  effects: tuple[Effect, ...]) -> dict[str, float]:
    """The share of its point's natural executions that each effect's outcome and detail had, in the repetitions and
    scopes the effect was compared in: how often a counterpart must act to stand for it."""
    outcomes: dict[tuple[str, str, tuple[tuple[str, str], ...]], int] = defaultdict(int)
    executions: dict[str, int] = defaultdict(int)
    for record in records:
        if record.rule is None and record.experiment in labels and record.scope in scopes:
            outcomes[(record.point, record.outcome, tuple(sorted(record.detail.items())))] += record.count
            executions[record.point] += record.count
    return {EffectKey.of(effect).key: outcomes[(effect.point, effect.outcome, tuple(sorted(effect.detail.items())))]
            / executions[effect.point] for effect in effects if executions.get(effect.point)}


def boundary_loads(records: list[ObservationRecord], labels: list[str], scope: str) -> dict[str, dict[str, Load]]:
    """Every rpc_server and rpc_client point of a scope, by outcome, with its executions per repetition and the mean
    of their totals, injected executions included, since the boundary is what callers see."""
    sums: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(lambda: [0.0, 0.0]))
    for record in records:
        if record.experiment in labels and record.scope == scope and point_kind(record.point) in BOUNDARY_KINDS:
            totals = sums[record.point][record.outcome]
            totals[0] += record.count
            totals[1] += record.total
    return {point: {outcome: Load(count=count / len(labels), mean=total / count)
                    for outcome, (count, total) in outcomes.items() if count} for point, outcomes in sums.items()}


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
    refusal: str | None = None
    """What a service said when it refused the fault's rule, which then never ran."""
    elapsed: dict[str, float] = {}
    """The mean time, in ms, the natural executions behind each count effect took in the treatment repetitions;
    records from before observations carried it have none."""
    boundary: dict[str, dict[str, Load]] = {}
    """How the treated tenant's service boundaries behaved, by rpc_server or rpc_client point and outcome, which tells
    whether a substitute run behaves as the natural run it stands for; records from before have none."""
    rates: dict[str, float] = {}
    """The share of its point's natural executions each effect's outcome had in the treatment repetitions; records
    from before it was kept have none."""
    seeds: tuple[int, ...] = ()
    """The FAULTPOINT_SEED of every treatment repetition, in the order of the labels; records from before repetitions
    had their own ran every repetition with the SDKs' default seed, 0."""

    @property
    def exercised(self) -> bool:
        return all(self.injected)


class EffectKey(BaseModel):
    """What identifies an effect across runs: its point, its outcome, the metric that grew and what else the
    executions had in common."""

    model_config = FROZEN

    point: str
    outcome: str
    metric: Metric
    detail: dict[str, str] = {}

    @property
    def key(self) -> str:
        return " ".join([self.point, self.outcome,
                         *(f"{name}={value}" for name, value in sorted(self.detail.items())), self.metric])

    @classmethod
    def of(cls, effect: Effect) -> Self:
        return cls(point=effect.point, outcome=effect.outcome, metric=effect.metric, detail=effect.detail)


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

    @property
    def scoped(self) -> bool:
        return all(fault.scoped for fault in self.faults)

    def tenants(self) -> list[str]:
        """Every other tenant, since the load interleaves the tenants and a fault can break the request after its own;
        a fault no rule can scope reaches every tenant, and the first stands for them."""
        return tenant_names(self.workload.workload)[::2][:len(self.faults)]

    def untreated(self) -> list[str]:
        return [tenant for tenant in tenant_names(self.workload.workload)
                if self.scoped and tenant not in self.tenants()]

    def ruleset(self, label: str) -> RuleSet:
        return RuleSet(experiment=label, rules=tuple(
            Rule(id=rule_id, point=fault.point, action=action, scope={SCOPE_KEY: tenant} if fault.scoped else {},
                 trigger=Trigger(probability=probability))
            for fault, tenant in zip(self.faults, self.tenants(), strict=True)
            for rule_id, (action, probability) in zip(
                fault.rule_ids(), [(fault.action, fault.probability),
                                   *((rule.action, rule.probability) for rule in fault.following)], strict=True)))


def control_labels(workload: NamedWorkload, repetitions: int) -> list[str]:
    return [f"{workload.name}.control.{index}" for index in range(repetitions)]


def pack(pairs: list[tuple[Fault, NamedWorkload]]) -> list[Group]:
    """Groups of faults of one workload that share repetitions; a delay runs alone, since it acts through what the
    tenants share (a connection, a lock, an event loop, the sequential load) and so leaks by construction, and so
    does a fault no rule can scope to a tenant."""
    by_workload: dict[str, list[Fault]] = defaultdict(list)
    workloads = {workload.name: workload for _, workload in pairs}
    for fault, workload in pairs:
        by_workload[workload.name].append(fault)
    groups = []
    for name, faults in by_workload.items():
        workload = workloads[name]
        capacity = len(tenant_names(workload.workload)) // 2
        shared = [fault for fault in faults if not fault.delays and fault.scoped]
        groups += [Group(workload=workload, faults=(fault,)) for fault in faults if fault.delays or not fault.scoped]
        groups += [Group(workload=workload, faults=tuple(shared[start:start + capacity]))
                   for start in range(0, len(shared), capacity)]
    return groups


def merge_scope_effects(scoped: tuple[Effect, ...], unscoped: tuple[Effect, ...]) -> tuple[Effect, ...]:
    shown = {(effect.point, effect.outcome, effect.metric) for effect in scoped}
    return (*scoped, *(effect for effect in unscoped
                      if (effect.point, effect.outcome, effect.metric) not in shown))


class Repetitions(ABC):
    """The repetitions of an experiment, by label, as observations, statuses, seeds and refusals, and the comparisons
    that turn a group's repetitions and its workload's controls into the group's treatment records."""

    def __init__(self, alpha: float, min_mean_increase: float) -> None:
        self.alpha = alpha
        self.min_mean_increase = min_mean_increase

    @abstractmethod
    def observations(self, label: str) -> list[ObservationRecord]: ...

    @abstractmethod
    def statuses(self, label: str) -> Statuses: ...

    @abstractmethod
    def seed(self, label: str) -> int: ...

    @abstractmethod
    def refusal(self, label: str) -> str | None:
        """What a service said when it refused a rule of the repetition, which then ended."""

    def comparison(self, control: tuple[str, ...], treatment: list[str], tenant: str) -> Comparison:
        records = [record for label in (*control, *treatment) for record in self.observations(label)]
        return compare(records, [Selection(experiment=label, scope=tenant) for label in control],
                       [Selection(experiment=label, scope=tenant) for label in treatment],
                       self.alpha, self.min_mean_increase)

    def group_records(self, group: Group, control: tuple[str, ...], labels: list[str]) -> list[TreatmentRecord]:
        """A record per fault: its tenant's comparison and, for a fault alone in its repetitions, the comparison of
        what no tenant scope covers, such as the kernel's view of the upstream components."""
        refusals = [refused for label in labels if (refused := self.refusal(label)) is not None]
        if refusals:
            return [TreatmentRecord(fault=fault, workload=group.workload.name, tenant=tenant, labels=tuple(labels),
                                    packed_with=tuple(other.key for other in group.faults if other != fault),
                                    injected=tuple(0 for _ in labels), statuses=tuple({} for _ in labels), effects=(),
                                    leakage={}, refusal=refusals[0])
                    for fault, tenant in zip(group.faults, group.tenants(), strict=True)]
        leakage = {tenant: effects for tenant in group.untreated()
                   if (effects := self.comparison(control, labels, tenant).effects)}
        unscoped = self.comparison(control, labels, UNSCOPED)
        observed = [record for label in labels for record in self.observations(label)]
        records = []
        for fault, tenant in zip(group.faults, group.tenants(), strict=True):
            comparison = self.comparison(control, labels, tenant)
            injected = [sum(injection.counts[index] for injection in (*comparison.injections, *unscoped.injections)
                            if injection.rule in fault.rule_ids()) for index in range(len(labels))]
            effects = (merge_scope_effects(comparison.effects, unscoped.effects)
                       if len(group.faults) == 1 else comparison.effects)
            records.append(TreatmentRecord(
                fault=fault, workload=group.workload.name, tenant=tenant, labels=tuple(labels),
                packed_with=tuple(other.key for other in group.faults if other != fault), injected=tuple(injected),
                statuses=tuple(self.statuses(label).tenants[tenant] for label in labels), effects=effects,
                leakage=leakage, elapsed=effects_elapsed(observed, labels, {tenant, UNSCOPED}, effects),
                boundary=boundary_loads(observed, labels, tenant),
                rates=effects_rates(observed, labels, {tenant, UNSCOPED}, effects),
                seeds=tuple(self.seed(label) for label in labels)))
        return records
