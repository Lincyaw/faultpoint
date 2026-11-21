from enum import StrEnum
from typing import Final, Literal, Self

from pydantic import BaseModel, Field, ImportString, JsonValue, model_validator

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


class Raising(BaseModel):
    """Raising an exception at a call site, constructed with an empty message: the class an importable dotted name
    gives, or else the first class the handlers around the call site name."""

    model_config = STRICT

    error: ImportString[type[BaseException]] | None = None


class RaiseFail(Raising):
    """Raising instead of running the call site's statement."""

    kind: Literal[ActionKind.FAIL]


class RaiseFailAfter(Raising):
    """Raising once the call site's statement completed, which keeps the exception the statement raised itself."""

    kind: Literal[ActionKind.FAIL_AFTER]


class Failure(BaseModel):
    """What the caller of a failed RPC sees: a synthetic response status or a boundary error."""

    model_config = STRICT

    error: BoundaryError | None = None
    status: int | None = Field(default=None, ge=100, le=599)


class BoundaryFail(Failure):
    kind: Literal[ActionKind.FAIL]


class FailAfter(Failure):
    """A failure the caller sees after the boundary's effect took place."""

    kind: Literal[ActionKind.FAIL_AFTER]


ONE_FAILURE: Final = "a failure names a peer error or a code, not both"
INJECTED_MESSAGE: Final = "faultpoint: injected failure"
"""The message of the client library's error that a failure with a code raises, since only the peer knows the text
that comes with the code."""


class StoreFailure(BaseModel):
    """What the caller of a failed store or message broker sees: a boundary error, or the client library's own error
    with the code the rule names."""

    model_config = STRICT

    error: BoundaryError | None = None
    code: str | None = Field(default=None, min_length=1)
    """The code the client library reports, such as a SQLSTATE or the prefix of a Redis error reply."""

    @model_validator(mode="after")
    def one_failure(self) -> Self:
        if self.error is not None and self.code is not None:
            raise ValueError(ONE_FAILURE)
        return self


class StoreFail(StoreFailure):
    kind: Literal[ActionKind.FAIL]


class StoreFailAfter(StoreFailure):
    """A failure the caller sees after the write or the message took place."""

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
