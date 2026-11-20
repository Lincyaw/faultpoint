from collections import defaultdict
from collections.abc import Iterable
from enum import StrEnum
from functools import cached_property
from hashlib import sha256
from pathlib import Path
from typing import Final, Self

from faultpoint.observations import ObservationRecord
from faultpoint.placement import Manifest
from faultpoint.rules import Action
from faultpoint.tools.kinds import KindTable
from pydantic import BaseModel, ConfigDict

FROZEN: Final = ConfigDict(frozen=True, extra="forbid")
DATA: Final = Path(__file__).resolve().parents[2] / "data"
ACTIONS_FILE: Final = DATA / "actions.json"
DELAY: Final = "delay"
KERNEL_KINDS: Final = frozenset({"syscall", "packet"})
LIBRARY_VERSION: Final = "@"
"""What a dependency library's point carries in its locator: the library's name and version."""
CONFIGURED_EXECUTIONS: Final = 1.0
"""What a configured point counts as executing in every scenario, since only its injections are observed."""


class Layer(StrEnum):
    BUSINESS = "business"
    LIBRARY = "library"
    UPSTREAM = "upstream"
    """An infrastructure component that runs as its own process, such as Redis or PostgreSQL."""
    KERNEL = "kernel"
    """The kernel under a business service: its system calls and packets."""


def point_kind(point: str) -> str:
    return point.split(":", 2)[1]


def point_service(point: str) -> str:
    return point.split(":", 1)[0]


def point_layer(point: str, upstream: frozenset[str]) -> Layer:
    if point_service(point) in upstream:
        return Layer.UPSTREAM
    if point_kind(point) in KERNEL_KINDS:
        return Layer.KERNEL
    return Layer.LIBRARY if LIBRARY_VERSION in point.split(":", 2)[2] else Layer.BUSINESS


class Fault(BaseModel):
    """An action at a point: what one injection does, and, through the effect map, what an effect stands for."""

    model_config = FROZEN

    point: str
    action: Action
    layer: Layer = Layer.BUSINESS
    scoped: bool = True
    """Whether a rule can limit the fault to a tenant; kernel points see no request baggage."""

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
    """The actions the search tries at a point of each kind, with their own list for points inside libraries."""

    model_config = FROZEN

    kinds: dict[str, tuple[Action, ...]]
    library: dict[str, tuple[Action, ...]] = {}

    @classmethod
    def read(cls, path: Path = ACTIONS_FILE) -> Self:
        return cls.model_validate_json(path.read_text(encoding="utf-8"))

    def actions(self, point: str, layer: Layer) -> tuple[Action, ...] | None:
        """The actions to try at a point, none when its kind has no list for its layer."""
        return (self.library if layer == Layer.LIBRARY else self.kinds).get(point_kind(point))


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


def control_executions(records: Iterable[ObservationRecord], repetitions: int, tenants: int,
                       kinds: KindTable) -> dict[str, float]:
    """The executions of every point the records show, per tenant and repetition: in a tenant's scope for the kinds a
    rule can scope, and outside any scope for those it cannot."""
    counts: dict[str, int] = defaultdict(int)
    for record in records:
        reached = record.scope != "" if kinds.kinds[point_kind(record.point)].scope else record.scope == ""
        counts[record.point] += record.count if reached else 0
    return {point: count / (repetitions * tenants) for point, count in counts.items()}


def build_catalog(manifests: Path, executions: dict[str, dict[str, float]], configured: list[str],
                  actions: ActionTable, kinds: KindTable, upstream: frozenset[str]) -> Catalog:
    """Every point the manifests list, a control observed or the deployment configures, times the actions its kind
    takes in its layer; the points no control executed where a rule reaches them are excluded."""
    placed = {entry.id for path in sorted(manifests.glob("*.json"))
              for entry in Manifest.model_validate_json(path.read_text(encoding="utf-8")).points}
    points = sorted(placed | set(configured) | {point for per_point in executions.values() for point in per_point})
    uses = tuple(PointUse(point=point, executions={
        scenario: CONFIGURED_EXECUTIONS if point in configured else per_point.get(point, 0.0)
        for scenario, per_point in executions.items()}) for point in points)
    excluded = [Exclusion(point=use.point, reason="no control executed it where a rule reaches it")
                for use in uses if not any(use.executions.values())]
    excluded += [Exclusion(point=use.point, reason=f"actions.json lists no action for {point_kind(use.point)} in "
                                                   f"the {point_layer(use.point, upstream)} layer")
                 for use in uses if any(use.executions.values())
                 and actions.actions(use.point, point_layer(use.point, upstream)) is None]
    skipped = {exclusion.point for exclusion in excluded}
    faults = tuple(Fault(point=use.point, action=action, layer=point_layer(use.point, upstream),
                         scoped=kinds.kinds[point_kind(use.point)].scope)
                   for use in uses if use.point not in skipped
                   for action in actions.actions(use.point, point_layer(use.point, upstream)) or ())
    return Catalog(faults=faults, uses=uses, excluded=tuple(excluded))
