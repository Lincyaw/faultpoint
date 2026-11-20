import { context, propagation, trace } from "@opentelemetry/api";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";
import { CompositePropagator, W3CBaggagePropagator, W3CTraceContextPropagator } from "@opentelemetry/core";

import type { ContextProvider } from "./core.js";

/** Boundaries carry trace context and baggage themselves, whatever the process configured. */
export const PROPAGATOR = new CompositePropagator({
  propagators: [new W3CTraceContextPropagator(), new W3CBaggagePropagator()],
});

/** The default context provider: OpenTelemetry baggage and trace context. */
export class OtelContext implements ContextProvider {
  constructor() {
    // The OpenTelemetry API keeps no request context unless a context manager is registered, so one is registered when the process has none.
    context.setGlobalContextManager(new AsyncLocalStorageContextManager().enable());
  }

  baggage(key: string): string | undefined {
    return propagation.getBaggage(context.active())?.getEntry(key)?.value;
  }

  traceId(): string | null {
    const spanContext = trace.getSpanContext(context.active());
    return spanContext !== undefined && trace.isSpanContextValid(spanContext) ? spanContext.traceId : null;
  }
}
