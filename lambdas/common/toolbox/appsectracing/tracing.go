package appsectracing

import (
	"context"
	"time"
)

// Span is a generic tracing span.  It may be a root span or sub span
type TracingSpan interface {
	// End the span
	End(context.Context)
	// Add an error to the span (and send an appsec log)
	AddError(err error)
	// LogKV Log a generic key value to the span
	LogKV(key string, value interface{})
	// GetStartTime gets the start time of the span, or time.Zero if nil
	GetStartTime() time.Time
}

// Tracer is a generic tracer.
// All the tracer needs to expose is the functionality to create a TracingSpan (adhearing to that interface)
// and functionality to close it.
type Tracer interface {
	StartSpan(ctx context.Context, operationName, operationType string) (TracingSpan, context.Context)
	Close(ctx context.Context) error
}
