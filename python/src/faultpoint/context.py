from typing import Final

from opentelemetry import baggage, trace
from opentelemetry.baggage.propagation import W3CBaggagePropagator
from opentelemetry.propagators.composite import CompositePropagator
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

PROPAGATOR: Final = CompositePropagator([TraceContextTextMapPropagator(), W3CBaggagePropagator()])
"""Boundaries carry trace context and baggage themselves, whatever the process configured."""


def scope_matches(scope: dict[str, str]) -> bool:
    return all(baggage.get_baggage(key) == value for key, value in scope.items())


def current_scope(key: str) -> str:
    value = baggage.get_baggage(key)
    return "" if value is None else str(value)


def current_trace_id() -> str | None:
    span_context = trace.get_current_span().get_span_context()
    return format(span_context.trace_id, "032x") if span_context.is_valid else None
