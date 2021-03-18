package appsectracing

import "context"

// Span is a generic tracing span.  It may be a root span or sub span
type TracingSpan interface {
	// End the span
	End(context.Context)
	// Add an error to the span (and send an appsec log)
	AddError(err error)
	// LogKV Log a generic key value to the span
	LogKV(key string, value interface{})
}

// Tracer is a tracer that can create and close spans
type Tracer interface {
	StartSpan(ctx context.Context, operationName, operationType string) (TracingSpan, context.Context)
	Close(ctx context.Context) error
}
