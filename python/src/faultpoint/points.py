from datetime import datetime, timedelta

from faultpoint.rules import Fail, Negate, SetValue, Shift
from faultpoint.runtime import RUNTIME


def branch(point: str, taken: bool) -> bool:
    """Whether a guarded error path runs: its natural condition, or forced by a fail rule."""
    if not RUNTIME.enabled:
        return taken
    rule = RUNTIME.decide(point)
    if rule is not None:
        RUNTIME.hold(rule.action)
        taken = taken or isinstance(rule.action, Fail)
    RUNTIME.record(point, "taken" if taken else "not_taken", 0.0, rule)
    return taken


def check(point: str, result: bool) -> bool:
    """The result of a detector, negated by a negate rule."""
    if not RUNTIME.enabled:
        return result
    rule = RUNTIME.decide(point)
    if rule is not None:
        RUNTIME.hold(rule.action)
        result = result != isinstance(rule.action, Negate)
    RUNTIME.record(point, "true" if result else "false", 0.0, rule)
    return result


def loop(point: str) -> None:
    """One iteration of a loop, delayed by a delay rule to model contention."""
    if not RUNTIME.enabled:
        return
    rule = RUNTIME.decide(point)
    if rule is not None:
        RUNTIME.hold(rule.action)
    RUNTIME.record(point, "iteration", 0.0, rule)


def value[T](point: str, observed: T) -> T:
    """A business value, replaced by a set rule or offset by a shift rule."""
    if not RUNTIME.enabled:
        return observed
    rule = RUNTIME.decide(point)
    result = observed
    if rule is not None:
        RUNTIME.hold(rule.action)
        if isinstance(rule.action, SetValue):
            result = rule.action.value
        if isinstance(rule.action, Shift):
            result = observed + rule.action.amount
    RUNTIME.record(point, "observed", float(result) if isinstance(result, int | float) else 0.0,
                   rule)
    return result


def clock[T: (float, datetime)](point: str, reading: T) -> T:
    """A clock reading, epoch seconds or a datetime, moved by a shift rule."""
    if not RUNTIME.enabled:
        return reading
    rule = RUNTIME.decide(point)
    result = reading
    if rule is not None:
        RUNTIME.hold(rule.action)
        if isinstance(rule.action, Shift):
            result = reading + (timedelta(seconds=rule.action.amount)
                                if isinstance(reading, datetime) else rule.action.amount)
    RUNTIME.record(point, "read", 0.0, rule)
    return result


def acquire(point: str, acquired: bool) -> bool:
    """Whether a resource was acquired: its natural outcome, or rejected by a fail rule."""
    if not RUNTIME.enabled:
        return acquired
    rule = RUNTIME.decide(point)
    if rule is not None:
        RUNTIME.hold(rule.action)
        acquired = acquired and not isinstance(rule.action, Fail)
    RUNTIME.record(point, "acquired" if acquired else "rejected", 0.0, rule)
    return acquired
