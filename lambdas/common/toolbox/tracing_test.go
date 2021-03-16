package toolbox

import (
	"context"
	"fmt"
	"testing"
)

func TestTracing(t *testing.T) {
	ctx := context.Background()

	tb := GetToolbox()
	defer tb.Close(ctx)

	// Try starting a span (should be a apm transaction)
	span, ctx := tb.StartSpan(ctx, "TestTransaction", "test.transaction.test")
	span.LogKV("testTransactionKey", "testValue")
	defer span.Close()

	// Start a span (should be a apm span)
	span, ctx = tb.StartSpan(ctx, "TestSpan", "test.span.test")
	span.LogKV("testSpanKey", "testValue")
	defer span.Close()

	// Start another span (should be a apm span)
	span, ctx = tb.StartSpan(ctx, "TestSpan2", "test.span.test")
	span.AddError(fmt.Errorf("test error"))
	defer span.Close()

	// Now manually go check APM to see if the correct structure appeared.
	// Also check appsec logging to see if the logs were sent correctly.
}
