// Package fpotel is the default context provider: it reads OpenTelemetry baggage and trace context, which an
// existing OpenTelemetry instrumentation or the fphttp adapter carries across services.
package fpotel

import (
	"context"

	"faultpoint"

	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/trace"
)

type provider struct{}

func (provider) Baggage(ctx context.Context, key string) string {
	return baggage.FromContext(ctx).Member(key).Value()
}

func (provider) TraceID(ctx context.Context) string {
	spanContext := trace.SpanContextFromContext(ctx)
	if !spanContext.IsValid() {
		return ""
	}
	return spanContext.TraceID().String()
}

func init() { faultpoint.UseContext(provider{}) }
