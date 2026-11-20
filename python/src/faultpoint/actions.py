from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, JsonValue

from faultpoint.rules import STRICT


class ActionKind(StrEnum):
    FAIL = "fail"
    FAIL_AFTER = "fail_after"
    DELAY = "delay"
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


class Fail(BaseModel):
    """Forcing the error path of an in-process point."""

    model_config = STRICT

    kind: Literal[ActionKind.FAIL]
    error: str | None = None
    """The registered error a call point returns."""


class Failure(BaseModel):
    """What the caller of a failed boundary sees: a synthetic response status or a boundary error."""

    model_config = STRICT

    error: BoundaryError | None = None
    status: int | None = Field(default=None, ge=100, le=599)


class BoundaryFail(Failure):
    kind: Literal[ActionKind.FAIL]


class FailAfter(Failure):
    """A failure the caller sees after the boundary's effect took place."""

    kind: Literal[ActionKind.FAIL_AFTER]


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
