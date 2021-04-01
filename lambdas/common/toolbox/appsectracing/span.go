package appsectracing

import (
	"context"
	"fmt"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing/appseclogging"
)

// Span is a generic span,
// providing some other functionality, like appsec logging errors.
type Span struct {
	operationName string
	operationType string
	// Key values logged during this span
	KV     map[string]interface{}
	span   TracingSpan
	logger *TracerLogger
}

func (s *Span) LogKV(key string, value interface{}) {
	if s.KV == nil {
		s.KV = map[string]interface{}{}
	}
	s.KV[key] = value
	s.span.LogKV(key, value)
}

func (s *Span) AddError(err error) {
	s.span.AddError(err)

	// AppSec Log error
	if !s.logger.NoDefaultAppSecLogging {
		s.logger.AppSecLogger.Error(err.Error(), map[string]map[string]string{"errorDetails": {"error": err.Error()}})
	}
}

func (s *Span) End(ctx context.Context) {
	// Log this as an appsec log
	if !s.logger.NoDefaultAppSecLogging {
		fields := appseclogging.Fields{"operationDetails": map[string]string{"operationType": s.operationType}}

		if len(s.KV) > 0 {
			fields["KeyValuePairs"] = map[string]string{}
			for key, value := range s.KV {
				fields["KeyValuePairs"][key] = fmt.Sprintf("%v", value)
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
