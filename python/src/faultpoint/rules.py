import re
from enum import StrEnum
from typing import Annotated, Final, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

STRICT: Final = ConfigDict(frozen=True, extra="forbid")


class PointKind(StrEnum):
    BRANCH = "branch"
    CALL = "call"
    CHECK = "check"
    LOOP = "loop"
    VALUE = "value"
    CLOCK = "clock"
    ACQUIRE = "acquire"
    RPC_CLIENT = "rpc_client"
    RPC_SERVER = "rpc_server"
    STORE_READ = "store_read"
    STORE_WRITE = "store_write"
    PUBLISH = "publish"
    CONSUME = "consume"
    SYSCALL = "syscall"
    PACKET = "packet"


class ActionKind(StrEnum):
    FAIL = "fail"
    DELAY = "delay"
    FAIL_AFTER = "fail_after"
    DROP = "drop"
    DUPLICATE = "duplicate"
    NEGATE = "negate"
    EMPTY = "empty"
    SET = "set"
    SHIFT = "shift"
    CRASH = "crash"


class BoundaryError(StrEnum):
    TIMEOUT = "timeout"
    REFUSED = "refused"


RPC_KINDS: Final = frozenset({PointKind.RPC_CLIENT, PointKind.RPC_SERVER})
BOUNDARY_KINDS: Final = RPC_KINDS | {PointKind.STORE_READ, PointKind.STORE_WRITE,
                                     PointKind.PUBLISH, PointKind.CONSUME}
KERNEL_KINDS: Final = frozenset({PointKind.SYSCALL, PointKind.PACKET})
"""Points the eBPF agent places, which see processes and sockets but no request baggage."""
ERRNO_NAME: Final = r"^E[A-Z0-9]+$"
HELD: Final = frozenset({ActionKind.DELAY, ActionKind.CRASH})
ALLOWED_ACTIONS: Final[dict[PointKind, frozenset[ActionKind]]] = {
    PointKind.BRANCH: HELD | {ActionKind.FAIL},
    PointKind.CALL: HELD | {ActionKind.FAIL},
    PointKind.CHECK: HELD | {ActionKind.NEGATE},
    PointKind.LOOP: HELD,
    PointKind.VALUE: HELD | {ActionKind.SET, ActionKind.SHIFT},
    PointKind.CLOCK: HELD | {ActionKind.SHIFT},
    PointKind.ACQUIRE: HELD | {ActionKind.FAIL},
    PointKind.RPC_CLIENT: HELD | {ActionKind.FAIL, ActionKind.FAIL_AFTER, ActionKind.DUPLICATE},
    PointKind.RPC_SERVER: HELD | {ActionKind.FAIL, ActionKind.FAIL_AFTER},
    PointKind.STORE_READ: HELD | {ActionKind.FAIL, ActionKind.EMPTY},
    PointKind.STORE_WRITE: HELD | {ActionKind.FAIL, ActionKind.FAIL_AFTER, ActionKind.DROP,
                                   ActionKind.DUPLICATE},
    PointKind.PUBLISH: HELD | {ActionKind.FAIL, ActionKind.FAIL_AFTER, ActionKind.DROP,
                               ActionKind.DUPLICATE},
    PointKind.CONSUME: HELD | {ActionKind.FAIL, ActionKind.FAIL_AFTER, ActionKind.DUPLICATE},
    PointKind.SYSCALL: frozenset({ActionKind.FAIL, ActionKind.CRASH}),
    PointKind.PACKET: frozenset({ActionKind.DELAY, ActionKind.DROP}),
}


def point_id(service: str, kind: PointKind, locator: str) -> str:
    if ":" in service:
        raise ValueError(f"a service name cannot contain ':': {service}")
    return f"{service}:{kind}:{locator}"


def point_kind(point: str) -> PointKind:
    parts = point.split(":", 2)
    if len(parts) != 3:
        raise ValueError(f"a point id is <service>:<kind>:<locator>: {point}")
    return PointKind(parts[1])


class Fail(BaseModel):
    model_config = STRICT

    kind: Literal[ActionKind.FAIL]
    error: str | None = None
    """A registered error name for a call point, a boundary error for a boundary point, or an
    errno name for a syscall point."""
    status: int | None = Field(default=None, ge=100, le=599)
    """The synthetic response status of an RPC point."""


class FailAfter(BaseModel):
    model_config = STRICT

    kind: Literal[ActionKind.FAIL_AFTER]
    error: BoundaryError | None = None
    status: int | None = Field(default=None, ge=100, le=599)


class Delay(BaseModel):
    model_config = STRICT

    kind: Literal[ActionKind.DELAY]
    ms: int = Field(gt=0)


class Drop(BaseModel):
    model_config = STRICT

    kind: Literal[ActionKind.DROP]


class Duplicate(BaseModel):
    model_config = STRICT

    kind: Literal[ActionKind.DUPLICATE]


class Negate(BaseModel):
    model_config = STRICT

    kind: Literal[ActionKind.NEGATE]


class Empty(BaseModel):
    model_config = STRICT

    kind: Literal[ActionKind.EMPTY]


class SetValue(BaseModel):
    model_config = STRICT

    kind: Literal[ActionKind.SET]
    value: JsonValue


class Shift(BaseModel):
    model_config = STRICT

    kind: Literal[ActionKind.SHIFT]
    amount: float = Field(allow_inf_nan=False)
    """Added to a numeric value, or seconds added to a clock reading."""


class Crash(BaseModel):
    model_config = STRICT

    kind: Literal[ActionKind.CRASH]
    code: int = Field(default=1, ge=0, le=255)


Action = Annotated[Fail | FailAfter | Delay | Drop | Duplicate | Negate | Empty | SetValue | Shift
                   | Crash, Field(discriminator="kind")]


class Trigger(BaseModel):
    model_config = STRICT

    skip: int = Field(default=0, ge=0)
    limit: int | None = Field(default=None, ge=1)
    probability: float = Field(default=1.0, gt=0, le=1)


class Rule(BaseModel):
    model_config = STRICT

    id: str = Field(min_length=1)
    point: str
    action: Action
    scope: dict[str, str] = Field(default_factory=dict)
    """Baggage entries a request must carry for the rule to apply."""
    trigger: Trigger = Field(default_factory=Trigger)

    @model_validator(mode="after")
    def validate_action(self) -> Self:
        kind = point_kind(self.point)
        action = self.action.kind
        if action not in ALLOWED_ACTIONS[kind]:
            raise ValueError(f"action {action} does not apply to a {kind} point")
        if kind in KERNEL_KINDS and self.scope:
            raise ValueError(f"a {kind} point sees no baggage, so its rule has no scope")
        if kind is PointKind.SYSCALL and isinstance(self.action, Fail) and (
                self.action.error is None or re.match(ERRNO_NAME, self.action.error) is None):
            raise ValueError("a syscall fails with an errno name such as ECONNREFUSED")
        if isinstance(self.action, Fail | FailAfter):
            if self.action.status is not None and kind not in RPC_KINDS:
                raise ValueError("only an RPC point responds with a status")
            if self.action.status is not None and self.action.error is not None:
                raise ValueError("a failure has either a status or an error")
            if kind is PointKind.RPC_SERVER and self.action.error is not None:
                raise ValueError("an RPC server fails with a status")
            if kind in BOUNDARY_KINDS and self.action.error is not None:
                BoundaryError(self.action.error)
        return self


class RuleSet(BaseModel):
    model_config = STRICT

    experiment: str = Field(min_length=1)
    rules: tuple[Rule, ...] = ()

    @model_validator(mode="after")
    def validate_identities(self) -> Self:
        identities = [rule.id for rule in self.rules]
        if len(identities) != len(set(identities)):
            raise ValueError("rule ids repeat")
        return self
