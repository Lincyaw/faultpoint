import json
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
DATA: Final = Path(__file__).resolve().parent / "data"
"""The effect map and the action table, which ship with the package and fix what one of its versions computes."""
ACTIONS_FILE: Final = DATA / "actions.json"
DELAY: Final = "delay"
PROBABILITY: Final = "probability"
"""How a fault's key names the chance that its rule acts on an execution."""
FOLLOWED_BY: Final = "then"
"""How a fault's key joins the rules after its own."""
FOLLOWING_SEPARATOR: Final = "-"
"""What joins a fault's digest and the index of a rule after its own in that rule's id."""
KERNEL_KINDS: Final = frozenset({"syscall", "packet"})
FUNCTION_KINDS: Final = frozenset({"call", "check"})
"""The kinds of the points the kernel agent places in an upstream component's functions."""
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


RPC_CLIENT: Final = "rpc_client"
RPC_SERVER: Final = "rpc_server"
BOUNDARY_KINDS: Final = frozenset({RPC_CLIENT, RPC_SERVER})
"""The kinds of the points where one service meets another."""


def point_kind(point: str) -> str:
    return point.split(":", 2)[1]


def point_service(point: str) -> str:
    return point.split(":", 1)[0]


def point_symbol(point: str) -> str:
    """The function a native function point is placed in, the end of its locator."""
    return point.rpartition(":")[2]


def point_layer(point: str, upstream: frozenset[str]) -> Layer:
    if point_service(point) in upstream:
        return Layer.UPSTREAM
    if point_kind(point) in KERNEL_KINDS:
        return Layer.KERNEL
    return Layer.LIBRARY if LIBRARY_VERSION in point.split(":", 2)[2] else Layer.BUSINESS


def point_scoped(point: str, layer: Layer, kinds: KindTable) -> bool:
    """Whether a rule can limit a point's fault to a tenant: its kind takes a scope and an SDK serves it, rather than
    the kernel agent, which sees no request baggage in an upstream component."""
    return kinds.kinds[point_kind(point)].scope and layer != Layer.UPSTREAM


def action_text(action: Action, probability: float) -> str:
    """An action's parameters sorted by name, a structured value such as fail's when as JSON with its keys sorted, so
    that the text, and the fault's key and digest, never depend on the order the parameters were written in."""
    parameters = [f"{name}={json.dumps(value, sort_keys=True) if isinstance(value, dict | list) else value}"
                  for name, value in sorted(action.model_dump(exclude={"kind"}).items())]
    chance = [f"{PROBABILITY}={probability}"] if probability < 1 else []
    return " ".join([action.kind, *parameters, *chance])


class Following(BaseModel):
    """A rule after a fault's own at its point, acting on the executions the rules before it left."""

    model_config = FROZEN

    action: Action
    probability: float = 1.0


class Fault(BaseModel):
    """An action at a point: what one injection does, and, through the effect map, what an effect stands for."""

    model_config = FROZEN

    point: str
    action: Action
    layer: Layer = Layer.BUSINESS
    scoped: bool = True
    """Whether a rule can limit the fault to a tenant; kernel points see no request baggage."""
    probability: float = 1.0
    """The chance that the rule acts on each execution it could act on, below 1 for a counterpart standing for an
    effect seen on part of the executions."""
    following: tuple[Following, ...] = ()
    """For a counterpart, the rules after its own that reproduce how the rest of the point's executions changed."""

    @property
    def key(self) -> str:
        return f" {FOLLOWED_BY} ".join([f"{self.point} {action_text(self.action, self.probability)}",
                                        *(action_text(rule.action, rule.probability) for rule in self.following)])

    @property
    def digest(self) -> str:
        return sha256(self.key.encode()).hexdigest()[:12]

    def rule_ids(self) -> tuple[str, ...]:
        """The ids of the fault's rules, its own first."""
        return self.digest, *(f"{self.digest}{FOLLOWING_SEPARATOR}{index}" for index in range(1, len(self.following) + 1))

    @property
    def delays(self) -> bool:
        return DELAY in {self.action.kind, *(rule.action.kind for rule in self.following)}

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
    functions: dict[str, tuple[Action, ...]] = {}
    """The actions at the points the kernel agent places in an upstream component's functions, by function, since a
    fail names one of the failures the agent's configuration defines for that function."""

    @classmethod
    def read(cls, path: Path = ACTIONS_FILE) -> Self:
        return cls.model_validate_json(path.read_text(encoding="utf-8"))

    def actions(self, point: str, layer: Layer) -> tuple[Action, ...] | None:
        """The actions to try at a point, none when its kind, or its function, has no list for its layer."""
        if layer == Layer.UPSTREAM and point_kind(point) in FUNCTION_KINDS:
            return self.functions.get(point_symbol(point))
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
    narrower: dict[str, tuple[str, ...]] = {}
    """The actions a point implements when its manifest lists fewer than its kind's, such as a Go call point kept at
    its check, which implements no fail."""

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
                       kinds: KindTable, upstream: frozenset[str]) -> dict[str, float]:
    """The executions of every point the records show, per tenant and repetition: in a tenant's scope for the points a
    rule can scope, and outside any scope for those it cannot."""
    counts: dict[str, int] = defaultdict(int)
    for record in records:
        reached = (record.scope != "" if point_scoped(record.point, point_layer(record.point, upstream), kinds)
                   else record.scope == "")
        counts[record.point] += record.count if reached else 0
    return {point: count / (repetitions * tenants) for point, count in counts.items()}


def read_manifests(directory: Path) -> tuple[Manifest, ...]:
    """A build's manifests, in the order of their file names."""
    return tuple(Manifest.model_validate_json(path.read_text(encoding="utf-8"))
                 for path in sorted(directory.glob("*.json")))


def point_manifests(manifests: tuple[Manifest, ...]) -> dict[str, Manifest]:
    """The manifest that lists each point, with its language and the errors its build registers: a service can have
    several, such as its SDK's and that of its native hook points; a point no manifest lists has none."""
    listed: dict[str, Manifest] = {}
    for manifest in manifests:
        for entry in manifest.points:
            if entry.id in listed:
                raise ValueError(f"{entry.id} is listed in the manifests of {listed[entry.id].service} and of "
                                 f"{manifest.service}")
            listed[entry.id] = manifest
    return listed


def build_catalog(manifests: tuple[Manifest, ...], executions: dict[str, dict[str, float]], configured: list[str],
                  actions: ActionTable, kinds: KindTable, upstream: frozenset[str]) -> Catalog:
    """Every point the manifests list, a control observed or the deployment configures, times the actions its kind
    takes in its layer that the point implements; the points no control executed where a rule reaches them are
    excluded."""
    entries = [entry for manifest in manifests for entry in manifest.points]
    placed = {entry.id for entry in entries}
    narrower = {entry.id: entry.actions for entry in entries if entry.actions is not None}
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
                         scoped=point_scoped(use.point, point_layer(use.point, upstream), kinds))
                   for use in uses if use.point not in skipped
                   for action in actions.actions(use.point, point_layer(use.point, upstream)) or ()
                   if implements(narrower, use.point, action))
    return Catalog(faults=faults, uses=uses, excluded=tuple(excluded), narrower=narrower)


def implements(narrower: dict[str, tuple[str, ...]], point: str, action: Action) -> bool:
    """Whether a point implements an action: every action of its kind, unless its manifest lists fewer."""
    return point not in narrower or action.kind in narrower[point]
