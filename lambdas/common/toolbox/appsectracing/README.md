# App Sec Tracing

This library provides tracing and appsec logging to your go application.

You create a new `TracerLogger` object which you can then trace your application and automatically or manually send appsec logs.

## How it works

By default, you can create "spans", which are time boxed groups of functionality.  You can create spans inside of other spans to create hierarchical events to...trace! You can also log key values to each individual spans.
Whenever you close a span, an application log is triggered with the operation name, type, and logged key values from that span.  You can disable this functionality by setting `TracerLogger.NoDefaultAppLogging = true`.

### Example

```go
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
span, ctx := tl.StartSpan(ctx, "PerformWork", "general.work")
span.LogKV("time", fmt.Sprintf("%v", time.Now()))
span.End(ctx)
```
