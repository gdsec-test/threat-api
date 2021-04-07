package appsectracing

import (
	"context"
	"fmt"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing/appseclogging"
)

// Span is a generic span, which tracks the start time, end time, and information about some event.
// Spans can be within other spans.
// By default, whenever a span ends, an AppLog is triggered with details about the span.
type Span struct {
	operationName    string
	operationType    string
	operationSubType string
	operationAction  string
	// Key values logged during this span
	KV map[string]interface{}
	// Any errors attached to this span
	Errors []error
	// the underlying span object (it's an interface, so it could be
	// any vendor implementation of a span, such as ELK APM)
	span TracingSpan
	// The root tracer logger object
	logger *TracerLogger
	// Indicated if this span is an appseclog event
	// https://github.secureserver.net/CTO/guidelines/blob/master/Standards-Best-Practices/Security/Application-Security-Logging-Standard.md
	appSecLogEvent bool
}

// LogKV Logs a generic key value to the span.  The underlying tracer implementation may
// handle this in different ways, but by default the finalized AppLogger will log out all
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
// this different ways.  By Default the AppLogger will immediately log the error.
// It will also add the error the list of errors in the span to be logged on the end of the span.
func (s *Span) AddError(err error) {
	s.span.AddError(err)
	if s.Errors == nil {
		s.Errors = []error{}
	}
	s.Errors = append(s.Errors, err)

	// App Log error
	if !s.logger.NoDefaultAppLogging {
		s.logger.AppLogger.Error(err.Error(), appseclogging.Fields{
			"errorDetails": {"error": err.Error()},
			"spanDetails":  {"spanStartTime": "s"},
		}, nil, nil)
	}
}

// End ends this span.  The span will be completed.
// By default the AppLogger will log the completed span with it's details,
// errors, and logged key values.
func (s *Span) End(ctx context.Context) {
	s.span.End(ctx)

	// Log this as an appsec log
	if !s.logger.NoDefaultAppLogging {
		fields := appseclogging.Fields{"operationDetails": map[string]string{
			"operationName": s.operationName,
			"operationType": s.operationType,
			"subType":       s.operationSubType,
			"action":        s.operationAction,
			"startTime":     fmt.Sprintf("%d", s.span.GetStartTime().UTC().Unix()),
			"endTime":       fmt.Sprintf("%d", s.span.GetEndTime().UTC().Unix()),
			// Duration in microseconds
			"duration": fmt.Sprintf("%d", s.span.GetStartTime().Sub(s.span.GetEndTime()).Microseconds()),
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

		tags := []string{}
		if s.appSecLogEvent {
			tags = []string{"security"}
		}

		s.logger.AppLogger.Info(s.operationName, fields, tags, nil)
	}
}

// StartSpan starts a new span.
// OperationName is the name of the operation, ex: ValidateJWT.
// Operation Type is the high level type, ex: auth, operation sub type is the sub type, ex: jwt,
// and operation action is the action description, ex: validate.
func (l *TracerLogger) StartSpan(ctx context.Context, operationName, operationType, operationSubType, operationAction string) (*Span, context.Context) {
	var span TracingSpan
	span, ctx = l.Tracer.StartSpan(ctx, operationName, operationType, operationSubType, operationAction)

	return &Span{
		operationName:    operationName,
		operationType:    operationType,
		operationSubType: operationSubType,
		operationAction:  operationAction,
		span:             span,
		logger:           l,
	}, ctx
}

// SetAppSecLogEvent sets this span to be an application security logging event.
// It will hence have the key-value pair logged of "AppSecLog"="true", and will log
// as a security event on span end.
// https://github.secureserver.net/CTO/guidelines/blob/master/Standards-Best-Practices/Security/Application-Security-Logging-Standard.md
func (s *Span) SetAppSecLogEvent(ctx context.Context) {
	s.appSecLogEvent = true
}
