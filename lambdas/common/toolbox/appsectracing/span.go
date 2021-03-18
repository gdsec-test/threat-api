package appsectracing

import (
	"context"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing/appseclogging"
)

// Span is a generic span,
// providing some other functionality, like appsec logging errors.
type Span struct {
	span   TracingSpan
	logger *TracerLogger
}

func (s *Span) LogKV(key string, value interface{}) {
	s.span.LogKV(key, value)
}

func (s *Span) AddError(err error) {
	s.span.AddError(err)

	// AppSec Log error
	if !s.logger.NoDefaultAppSecLogging {
		s.logger.AppSecLogger.Error(err.Error(), map[string]map[string]string{"errorDetails": {"error": err.Error()}})
	}
}

func (s *Span) Close(ctx context.Context) {
	s.span.Close(ctx)
}

// StartSpan starts a new span.
// The operationType is in the format of type.subtype.action.  For example: db.sql.query.
func (l *TracerLogger) StartSpan(ctx context.Context, operationName, operationType string) (*Span, context.Context) {
	var span TracingSpan
	span, ctx = l.Tracer.StartSpan(ctx, operationName, operationType)

	// Log this as an appsec log
	if !l.NoDefaultAppSecLogging {
		l.AppSecLogger.Info(operationName, appseclogging.Fields{"operationDetails": map[string]string{"operationType": operationType}})
	}

	return &Span{span: span, logger: l}, ctx
}
