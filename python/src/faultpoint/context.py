from collections.abc import Iterator, Mapping, MutableMapping
from contextlib import AbstractContextManager, contextmanager
from typing import Final, Protocol

from opentelemetry import baggage, trace
from opentelemetry import context as otel_context
from opentelemetry.baggage.propagation import W3CBaggagePropagator
from opentelemetry.propagators.composite import CompositePropagator
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

PROPAGATOR: Final = CompositePropagator([TraceContextTextMapPropagator(), W3CBaggagePropagator()])


class ContextProvider(Protocol):
    def baggage(self, key: str) -> str | None: ...

    def trace_id(self) -> str | None: ...

    def attach(self, headers: Mapping[str, str]) -> AbstractContextManager[None]:
        """Make the request context the headers carry current while the block runs."""
        ...

    def inject(self, headers: MutableMapping[str, str]) -> None: ...


class OtelContext:
    """The OpenTelemetry context, whose W3C headers boundaries carry whatever propagators the process configured."""

    def baggage(self, key: str) -> str | None:
        value = baggage.get_baggage(key)
        return None if value is None else str(value)

    def trace_id(self) -> str | None:
        span_context = trace.get_current_span().get_span_context()
        return format(span_context.trace_id, "032x") if span_context.is_valid else None

    @contextmanager
    def attach(self, headers: Mapping[str, str]) -> Iterator[None]:
        token = otel_context.attach(PROPAGATOR.extract(headers, otel_context.get_current()))
        try:
            yield
        finally:
            otel_context.detach(token)

    def inject(self, headers: MutableMapping[str, str]) -> None:
        PROPAGATOR.inject(headers)
