package appsectracing

import (
	"context"
	"fmt"
	"time"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing/appseclogging"
	"go.elastic.co/apm"
)

func Example() {
	ctx := context.Background()

	// Create APM tracer.
	// You can theoretically use any tracing backend as long as it confines
	// to the Tracer interface.
	apmTracerRaw, _ := apm.NewTracerOptions(apm.TracerOptions{})
	apmTracer := NewAPMTracer(apmTracerRaw)

	// Create appsec logger
	appSecLogger := appseclogging.NewLogger([]string{}, map[string]string{"environment": "prod"})

	// Create TracerLogger
	tl := NewTracerLogger(apmTracer, appSecLogger)
	defer tl.Close(ctx)

	// Start a span!
	span, ctx := tl.StartSpan(ctx, "PerformWork", "general", "", "work")
	span.LogKV("time", fmt.Sprintf("%v", time.Now()))
	span.End(ctx)
}
