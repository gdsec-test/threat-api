package toolbox

import (
	"context"
	"fmt"
	"testing"
)

// This test makes sure appsec logging and tracing are working correctly.
// It does require manually cheking of the output logs and APM.
func TestTracingLogger(t *testing.T) {
	ctx := context.Background()

	tb := GetToolbox()
	defer tb.Close(ctx)

	// Try starting a span (should be a apm transaction)
	span, ctx := tb.TracerLogger.StartSpan(ctx, "TestTransaction", "test.transaction.test")
	span.LogKV("testTransactionKey", "testValue")
	defer span.Close(ctx)

	// Start a span (should be a apm span)
	span, ctx = tb.TracerLogger.StartSpan(ctx, "TestSpan", "test.span.test")
	span.LogKV("testSpanKey", "testValue")
	defer span.Close(ctx)

	// Start another span (should be a apm span)
	span, ctx = tb.TracerLogger.StartSpan(ctx, "TestSpan2", "test.span.test")
	// Should send an appsec log
	span.AddError(fmt.Errorf("test error"))
	defer span.Close(ctx)
}
