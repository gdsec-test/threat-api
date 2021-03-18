package appsectracing

import (
	"context"
	"fmt"
	"testing"
)

func TestTracing(t *testing.T) {
	ctx := context.Background()

	// TODO: Add testing logger
	// logger := NewTracerLogger()
	var logger TracerLogger

	// Try starting a span (should be a apm transaction)
	span, ctx := logger.StartSpan(ctx, "TestTransaction", "test.transaction.test")
	span.LogKV("testTransactionKey", "testValue")
	defer span.Close(ctx)

	// Start a span (should be a apm span)
	span, ctx = logger.StartSpan(ctx, "TestSpan", "test.span.test")
	span.LogKV("testSpanKey", "testValue")
	defer span.Close(ctx)

	// Start another span (should be a apm span)
	span, ctx = logger.StartSpan(ctx, "TestSpan2", "test.span.test")
	span.AddError(fmt.Errorf("test error"))
	defer span.Close(ctx)

	// Now manually go check APM to see if the correct structure appeared.
	// Also check appsec logging to see if the logs were sent correctly.
}
