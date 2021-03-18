// Package appsectracing provides a common package to provide both go tracing and appsec logging at the same time
package appsectracing

import (
	"context"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing/appseclogging"
	"go.elastic.co/apm"
)

// TracerLogger is a tool that supports tracing and appsec logging.
// By default it logs all root spans as an app sec log, or any errors.
// You can disable this by setting NoDefaultAppSecLogging.
type TracerLogger struct {
	NoDefaultAppSecLogging bool
	AppSecLogger           *appseclogging.AppSecLogger
	Tracer                 Tracer
}

// NewTracerLogger Creates a new logger with the provided tracer and appseclogger
func NewTracerLogger(tracer Tracer, appSecLogger *appseclogging.AppSecLogger) *TracerLogger {
	// Handle nil cases to do default noop behavior
	if tracer == nil {
		tracer = &APMTracer{apm.DefaultTracer}
	}
	if appSecLogger == nil {
		appSecLogger = appseclogging.NewLogger(nil, nil)
	}
	return &TracerLogger{AppSecLogger: appSecLogger, Tracer: tracer}
}

// Close the tracer and logger
func (t *TracerLogger) Close(ctx context.Context) error {
	return t.Tracer.Close(ctx)
}
