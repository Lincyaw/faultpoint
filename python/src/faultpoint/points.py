import time
from collections.abc import Callable
from datetime import date, timedelta
from enum import StrEnum
from types import TracebackType
from typing import Any, Final

import faultpoint.runtime
from faultpoint.actions import Crash, Delay, Fail, Negate, RaiseFail, RaiseFailAfter, Raising, SetValue, Shift
from faultpoint.observations import DetailKey, elapsed_ms, error_type
from faultpoint.runtime import Decision, Plugin, Runtime, implemented_actions

INJECTED_MESSAGE: Final = ""


class PointKind(StrEnum):
    """The in-process kinds; placed code calls the function of this module named after the kind."""

    BRANCH = "branch"
    CALL = "call"
    CHECK = "check"
    LOOP = "loop"
    VALUE = "value"
    CLOCK = "clock"
    ACQUIRE = "acquire"


class PointOutcome(StrEnum):
    TAKEN = "taken"
    NOT_TAKEN = "not_taken"
    OK = "ok"
    ERROR = "error"
    TRUE = "true"
    FALSE = "false"
    ITERATION = "iteration"
    OBSERVED = "observed"
    READ = "read"
    ACQUIRED = "acquired"
    REJECTED = "rejected"


PLUGIN: Final = Plugin(actions={
    PointKind.BRANCH: implemented_actions(Fail, Delay, Crash),
    PointKind.CALL: implemented_actions(RaiseFail, RaiseFailAfter, Delay, Crash),
    PointKind.CHECK: implemented_actions(Negate, Delay, Crash),
    PointKind.LOOP: implemented_actions(Delay, Crash),
    PointKind.VALUE: implemented_actions(SetValue, Shift, Delay, Crash),
    PointKind.CLOCK: implemented_actions(Shift, Delay, Crash),
    PointKind.ACQUIRE: implemented_actions(Fail, Delay, Crash),
})


def decide_in_process(runtime: Runtime, point: str) -> Decision | None:
    """The decision of an in-process point, whose delay blocks the thread as contention does; the point functions
    run it as the SDK's own work."""
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
    with runtime.own:
        decision = decide_in_process(runtime, point)
        match decision:
            case Decision(action=Fail()):
                taken = True
        runtime.observe(point, PointOutcome.TAKEN if taken else PointOutcome.NOT_TAKEN, 0.0, 0.0, decision)
    return taken


class CallSite:
    """A statement with a call inside a try block: a fail rule raises an exception the try's handlers catch before
    the statement runs, a fail_after rule once it completed without one, and whatever exception leaves it is an
    error."""

    def __init__(self, runtime: Runtime, point: str, candidates: Callable[[], tuple[type[BaseException], ...]]) -> None:
        self.runtime = runtime
        self.point = point
        self.candidates = candidates
        self.decision: Decision | None = None
        self.started = time.monotonic()

    def raised(self, raising: Raising) -> BaseException:
        """The exception a rule raises, observed as the call site's error."""
        raised = self.candidates()[0] if raising.error is None else raising.error
        self.runtime.observe(self.point, PointOutcome.ERROR, 0.0, elapsed_ms(self.started), self.decision,
                             {DetailKey.ERROR: error_type(raised)})
        return raised(INJECTED_MESSAGE)

    def __enter__(self) -> None:
        raised = None
        with self.runtime.own:
            self.decision = decide_in_process(self.runtime, self.point)
            match self.decision:
                case Decision(action=RaiseFail() as raising):
                    raised = self.raised(raising)
        if raised is not None:
            raise raised

    def __exit__(self, kind: type[BaseException] | None, error: BaseException | None,
                 trace: TracebackType | None) -> None:
        raised = None
        with self.runtime.own:
            if kind is None and self.decision is None:
                self.decision = self.runtime.decide_completed(self.point)
            match kind, self.decision:
                case None, Decision(action=RaiseFailAfter() as raising):
                    raised = self.raised(raising)
                case None, _:
                    self.runtime.observe(self.point, PointOutcome.OK, 0.0, elapsed_ms(self.started), self.decision)
                case _:
                    self.runtime.observe(self.point, PointOutcome.ERROR, 0.0, elapsed_ms(self.started), self.decision,
                                         {DetailKey.ERROR: error_type(kind)})
        if raised is not None:
            raise raised


def call(point: str, candidates: Callable[[], tuple[type[BaseException], ...]]) -> CallSite:
    return CallSite(faultpoint.runtime.RUNTIME, point, candidates)


def check(point: str, result: bool) -> bool:
    """The result of a detector, negated by a negate rule."""
    runtime = faultpoint.runtime.RUNTIME
    with runtime.own:
        decision = decide_in_process(runtime, point)
        match decision:
            case Decision(action=Negate()):
                result = not result
        runtime.observe(point, PointOutcome.TRUE if result else PointOutcome.FALSE, 0.0, 0.0, decision)
    return result


def loop(point: str) -> None:
    runtime = faultpoint.runtime.RUNTIME
    with runtime.own:
        started = time.monotonic()
        decision = decide_in_process(runtime, point)
        runtime.observe(point, PointOutcome.ITERATION, 0.0, elapsed_ms(started), decision)


def value(point: str, observed: Any) -> Any:
    """A business value, replaced by a set rule or offset by a shift rule."""
    runtime = faultpoint.runtime.RUNTIME
    with runtime.own:
        decision = decide_in_process(runtime, point)
        match decision:
            case Decision(action=SetValue(value=replacement)):
                observed = replacement
            case Decision(action=Shift(amount=amount)):
                observed = observed + amount
        runtime.observe(point, PointOutcome.OBSERVED,
                        float(observed) if isinstance(observed, int | float) else 0.0, 0.0, decision)
    return observed


def clock(point: str, reading: Any) -> Any:
    """A clock reading, epoch seconds or a date, moved by a shift rule of seconds."""
    runtime = faultpoint.runtime.RUNTIME
    with runtime.own:
        decision = decide_in_process(runtime, point)
        match decision:
            case Decision(action=Shift(amount=amount)):
                reading = reading + (timedelta(seconds=amount) if isinstance(reading, date) else amount)
        runtime.observe(point, PointOutcome.READ, 0.0, 0.0, decision)
    return reading


def acquire(point: str, acquired: bool) -> bool:
    """Whether a resource was acquired: its natural outcome, or rejected by a fail rule."""
    runtime = faultpoint.runtime.RUNTIME
    with runtime.own:
        started = time.monotonic()
        decision = decide_in_process(runtime, point)
        match decision:
            case Decision(action=Fail()):
                acquired = False
        runtime.observe(point, PointOutcome.ACQUIRED if acquired else PointOutcome.REJECTED, 0.0,
                        elapsed_ms(started), decision)
    return acquired
