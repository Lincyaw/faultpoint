import time
from datetime import date, timedelta
from enum import StrEnum
from typing import Any, Final

import faultpoint.runtime
from faultpoint.actions import Crash, Delay, Fail, Negate, SetValue, Shift
from faultpoint.runtime import Decision, Plugin, Runtime, implemented_actions


class PointKind(StrEnum):
    """The in-process kinds; placed code calls the function of this module named after the kind."""

    BRANCH = "branch"
    CHECK = "check"
    LOOP = "loop"
    VALUE = "value"
    CLOCK = "clock"
    ACQUIRE = "acquire"


class PointOutcome(StrEnum):
    TAKEN = "taken"
    NOT_TAKEN = "not_taken"
    TRUE = "true"
    FALSE = "false"
    ITERATION = "iteration"
    OBSERVED = "observed"
    READ = "read"
    ACQUIRED = "acquired"
    REJECTED = "rejected"


PLUGIN: Final = Plugin(actions={
    PointKind.BRANCH: implemented_actions(Fail, Delay, Crash),
    PointKind.CHECK: implemented_actions(Negate, Delay, Crash),
    PointKind.LOOP: implemented_actions(Delay, Crash),
    PointKind.VALUE: implemented_actions(SetValue, Shift, Delay, Crash),
    PointKind.CLOCK: implemented_actions(Shift, Delay, Crash),
    PointKind.ACQUIRE: implemented_actions(Fail, Delay, Crash),
})


def decide_in_process(runtime: Runtime, point: str) -> Decision | None:
    """The decision of an in-process point, whose delay blocks the thread as contention does."""
    decision = runtime.decide(point)
    match decision:
        case Decision(action=Delay(ms=ms)):
            time.sleep(ms / 1000)
        case Decision(action=Crash(code=code)):
            runtime.crash(code)
    return decision


def branch(point: str, taken: bool) -> bool:
    """Whether a guarded error path runs: its natural condition, or forced by a fail rule."""
    runtime = faultpoint.runtime.RUNTIME
    decision = decide_in_process(runtime, point)
    match decision:
        case Decision(action=Fail()):
            taken = True
    runtime.observe(point, PointOutcome.TAKEN if taken else PointOutcome.NOT_TAKEN, 0.0, decision)
    return taken


def check(point: str, result: bool) -> bool:
    """The result of a detector, negated by a negate rule."""
    runtime = faultpoint.runtime.RUNTIME
    decision = decide_in_process(runtime, point)
    match decision:
        case Decision(action=Negate()):
            result = not result
    runtime.observe(point, PointOutcome.TRUE if result else PointOutcome.FALSE, 0.0, decision)
    return result


def loop(point: str) -> None:
    runtime = faultpoint.runtime.RUNTIME
    runtime.observe(point, PointOutcome.ITERATION, 0.0, decide_in_process(runtime, point))


def value(point: str, observed: Any) -> Any:
    """A business value, replaced by a set rule or offset by a shift rule."""
    runtime = faultpoint.runtime.RUNTIME
    decision = decide_in_process(runtime, point)
    match decision:
        case Decision(action=SetValue(value=replacement)):
            observed = replacement
        case Decision(action=Shift(amount=amount)):
            observed = observed + amount
    runtime.observe(point, PointOutcome.OBSERVED,
                    float(observed) if isinstance(observed, int | float) else 0.0, decision)
    return observed


def clock(point: str, reading: Any) -> Any:
    """A clock reading, epoch seconds or a date, moved by a shift rule of seconds."""
    runtime = faultpoint.runtime.RUNTIME
    decision = decide_in_process(runtime, point)
    match decision:
        case Decision(action=Shift(amount=amount)):
            reading = reading + (timedelta(seconds=amount) if isinstance(reading, date) else amount)
    runtime.observe(point, PointOutcome.READ, 0.0, decision)
    return reading


def acquire(point: str, acquired: bool) -> bool:
    """Whether a resource was acquired: its natural outcome, or rejected by a fail rule."""
    runtime = faultpoint.runtime.RUNTIME
    decision = decide_in_process(runtime, point)
    match decision:
        case Decision(action=Fail()):
            acquired = False
    runtime.observe(point, PointOutcome.ACQUIRED if acquired else PointOutcome.REJECTED, 0.0, decision)
    return acquired
