// Package appsectracing provides a common package to provide both go tracing and appsec logging at the same time
package appsectracing

import (
	"context"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing/appseclogging"
	"go.elastic.co/apm"
)

// TracerLogger is a tool that supports tracing and application / application security logging.
// By default it logs all errors, and spans on their completion.
// You can disable this by setting NoDefaultAppLogging.
type TracerLogger struct {
	// This will turn of any default triggered appsec logs.  So any
	// app sec logging you want to do will be manual.
	NoDefaultAppLogging bool
	AppLogger           *appseclogging.AppLogger
	Tracer              Tracer
}

// NewTracerLogger Creates a new logger with the provided tracer and appseclogger
func NewTracerLogger(tracer Tracer, appSecLogger *appseclogging.AppLogger) *TracerLogger {
	// Handle nil cases to do default noop behavior
	if tracer == nil {
		tracer = &APMTracer{apm.DefaultTracer}
	}
	if appSecLogger == nil {
		appSecLogger = appseclogging.NewLogger(nil, nil)
	}
	return &TracerLogger{AppLogger: appSecLogger, Tracer: tracer}
}

// Close the tracer and logger.
// This should _always_ be called after you are done using this.
// Some underlying implementations require flushing.
func (t *TracerLogger) Close(ctx context.Context) error {
	return t.Tracer.Close(ctx)
}
