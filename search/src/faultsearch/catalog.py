from collections import defaultdict
from collections.abc import Iterable
from functools import cached_property
from hashlib import sha256
from pathlib import Path
from typing import Final, Self

from faultpoint.observations import ObservationRecord
from faultpoint.placement import Manifest
from faultpoint.rules import Action
from pydantic import BaseModel, ConfigDict

FROZEN: Final = ConfigDict(frozen=True, extra="forbid")
DATA: Final = Path(__file__).resolve().parents[2] / "data"
ACTIONS_FILE: Final = DATA / "actions.json"
DELAY: Final = "delay"


def point_kind(point: str) -> str:
    return point.split(":", 2)[1]


def point_service(point: str) -> str:
    return point.split(":", 1)[0]


class Fault(BaseModel):
    """An action at a point: what one injection does, and, through the effect map, what an effect stands for."""

    model_config = FROZEN

    point: str
    action: Action

    @property
    def key(self) -> str:
        parameters = sorted(self.action.model_dump(exclude={"kind"}).items())
        return " ".join([self.point, self.action.kind, *(f"{name}={value}" for name, value in parameters)])

    @property
    def digest(self) -> str:
        return sha256(self.key.encode()).hexdigest()[:12]

    @property
    def delays(self) -> bool:
        return self.action.kind == DELAY

    def instance_of(self, point: str, template: Action) -> bool:
        """Whether this fault is a template's action at a point: the same kind and every parameter the template names."""
        parameters = self.action.model_dump()
        return self.point == point and all(parameters.get(name) == value
                                           for name, value in template.model_dump().items())


class ActionTable(BaseModel):
    """The actions the search tries at a point of each kind."""

    model_config = FROZEN

    kinds: dict[str, tuple[Action, ...]]

    @classmethod
    def read(cls, path: Path = ACTIONS_FILE) -> Self:
        return cls.model_validate_json(path.read_text(encoding="utf-8"))


class PointUse(BaseModel):
    """How often the controls of each scenario executed a point, per tenant and repetition."""

    model_config = FROZEN

    point: str
    executions: dict[str, float]


class Exclusion(BaseModel):
    model_config = FROZEN

    point: str
    reason: str


class Catalog(BaseModel):
    model_config = FROZEN

    faults: tuple[Fault, ...]
    uses: tuple[PointUse, ...]
    excluded: tuple[Exclusion, ...]

    @cached_property
    def executions(self) -> dict[str, dict[str, float]]:
        return {use.point: use.executions for use in self.uses}

    @cached_property
    def by_key(self) -> dict[str, Fault]:
        return {fault.key: fault for fault in self.faults}

    def scenarios_executing(self, fault: Fault, order: list[str]) -> list[str]:
        """The scenarios whose controls executed a fault's point, most executions first, ties in the given order."""
        executions = self.executions[fault.point]
        return sorted((name for name in order if executions.get(name, 0) > 0),
                      key=lambda name: (-executions[name], order.index(name)))


def tenant_executions(records: Iterable[ObservationRecord], repetitions: int, tenants: int) -> dict[str, float]:
    """The executions of every point the records show, in a tenant's scope, per tenant and repetition."""
    counts: dict[str, int] = defaultdict(int)
    for record in records:
        counts[record.point] += record.count if record.scope else 0
    return {point: count / (repetitions * tenants) for point, count in counts.items()}


def build_catalog(manifests: Path, executions: dict[str, dict[str, float]], actions: ActionTable) -> Catalog:
    """Every point the manifests list or a control observed, times the actions its kind takes; the points no control
    executed in a tenant's scope are excluded, since a scoped rule never reaches them."""
    placed = {entry.id for path in sorted(manifests.glob("*.json"))
              for entry in Manifest.model_validate_json(path.read_text(encoding="utf-8")).points}
    points = sorted(placed | {point for per_point in executions.values() for point in per_point})
    uses = tuple(PointUse(point=point, executions={scenario: per_point.get(point, 0.0)
                                                   for scenario, per_point in executions.items()})
                 for point in points)
    excluded = [Exclusion(point=use.point, reason="no control executed it in a tenant's scope")
                for use in uses if not any(use.executions.values())]
    excluded += [Exclusion(point=use.point, reason=f"actions.json lists no action for {point_kind(use.point)}")
                 for use in uses if any(use.executions.values()) and point_kind(use.point) not in actions.kinds]
    skipped = {exclusion.point for exclusion in excluded}
    faults = tuple(Fault(point=use.point, action=action) for use in uses if use.point not in skipped
                   for action in actions.kinds[point_kind(use.point)])
    return Catalog(faults=faults, uses=uses, excluded=tuple(excluded))
