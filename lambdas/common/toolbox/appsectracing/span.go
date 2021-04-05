package appsectracing

import (
	"context"
	"fmt"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing/appseclogging"
)

// Span is a generic span, which tracks the start time, end time, and information about some event.
// Spans can be within other spans.
// By default, whenever a span ends, an AppSecLog is triggered with details about the span.
type Span struct {
	operationName string
	operationType string
	// Key values logged during this span
	KV map[string]interface{}
	// Any errors attached to this span
	Errors []error
	// the underlying span object (it's an interface, so it could be
	// any vendor implementation of a span, such as ELK APM)
	span TracingSpan
	// The root tracer logger object
	logger *TracerLogger
}

// LogKV Logs a generic key value to the span.  The underlying tracer implementation may
// handle this in different ways, but by default the finalized AppSecLogger will log out all
// span key/values when the span finishes.  The span's logged key/values may be accessed through
// the KV variable.
func (s *Span) LogKV(key string, value interface{}) {
	if s.KV == nil {
		s.KV = map[string]interface{}{}
	}
	s.KV[key] = value
	s.span.LogKV(key, value)
}

// AddError adds an error to the span.  The underlying tracer implementation may handle
// this different ways.  By Default the AppSecLogger will immediately log the error.
// It will also add the error the list of errors in the span to be logged on the end of the span.
func (s *Span) AddError(err error) {
	s.span.AddError(err)
	if s.Errors == nil {
		s.Errors = []error{}
	}
	s.Errors = append(s.Errors, err)

	// AppSec Log error
	if !s.logger.NoDefaultAppSecLogging {
		s.logger.AppSecLogger.Error(err.Error(), appseclogging.Fields{
			"errorDetails": {"error": err.Error()},
			"spanDetails":  {"spanStartTime": "s"},
		})
	}
}

// End ends this span.  The span will be completed.
// By default the AppSecLogger will log the completed span with it's details,
// errors, and logged key values.
func (s *Span) End(ctx context.Context) {
	// Log this as an appsec log
	if !s.logger.NoDefaultAppSecLogging {
		fields := appseclogging.Fields{"operationDetails": map[string]string{
			"operationType": s.operationType,
			"startTime":     fmt.Sprintf("%d", s.span.GetStartTime().Unix()),
		}}

		if len(s.KV) > 0 {
			fields["KeyValuePairs"] = map[string]string{}
			for key, value := range s.KV {
				fields["KeyValuePairs"][key] = fmt.Sprintf("%v", value)
			}
		}

		if len(s.Errors) > 0 {
			fields["errors"] = map[string]string{}
			for i, err := range s.Errors {
				fields["errors"][fmt.Sprintf("%d", i)] = err.Error()
			}
		}

		s.logger.AppSecLogger.Info(s.operationName, fields)
	}

	s.span.End(ctx)
}

// StartSpan starts a new span.
// The operationType is in the format of type.subtype.action.  For example: db.sql.query.
func (l *TracerLogger) StartSpan(ctx context.Context, operationName, operationType string) (*Span, context.Context) {
	var span TracingSpan
	span, ctx = l.Tracer.StartSpan(ctx, operationName, operationType)

	return &Span{
		operationName: operationName,
		operationType: operationType,
		span:          span,
		logger:        l,
	}, ctx
}
