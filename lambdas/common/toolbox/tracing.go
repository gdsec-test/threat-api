package toolbox

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"go.elastic.co/apm"
	"go.elastic.co/apm/module/apmhttp"
	"go.elastic.co/apm/transport"
)

// This file contains useful tools and object for tracing and logging

// GetHTTPClient wraps the provided http client into a new one that send stats to our tracing server.
// If nil is provided, then http.DefaultClient will be wrapped.
func (t *Toolbox) GetHTTPClient(inputClient *http.Client) *http.Client {
	return apmhttp.WrapClient(inputClient)
}

// InitAPM gets the APM config from secrets manager
func (t *Toolbox) InitAPM(ctx context.Context) error {
	// Close the default tracer
	// See this for why we do this: https://pkg.go.dev/go.elastic.co/apm#NewTracerOptions
	apm.DefaultTracer.Close()

	// Fetch config from credential store
	paramsToFetch := map[string]string{
		"ELASTIC_APM_SERVER_URL":   "",
		"ELASTIC_APM_SECRET_TOKEN": "",
	}
	for key := range paramsToFetch {
		secret, err := t.GetFromCredentialsStore(ctx, "/ThreatTools/Integrations/"+key, nil)
		if err != nil {
			return fmt.Errorf("error fetching %s from credential store: %w", key, err)
		}
		paramsToFetch[key] = *secret.SecretString
	}

	// Set ENV vars from parameter store
	// I know it's silly to the config for the APM tracer like this,
	// but it looks like this is the only way to do it...BAD DESIGN!
	// https://github.com/elastic/apm-agent-go/issues/618
	for key, value := range paramsToFetch {
		os.Setenv(key, value)
	}

	// Re-init the default tracer with this config
	transport, err := transport.InitDefault()
	if err != nil {
		return fmt.Errorf("error creating transport, probably a problem with the config: %w", err)
	}

	// Create the new tracer
	tracer, err := apm.NewTracerOptions(apm.TracerOptions{
		ServiceName: os.Getenv("AWS_LAMBDA_FUNCTION_NAME"), // TODO: How should we set this?
		Transport:   transport,
	})
	if err != nil {
		return fmt.Errorf("error creating tracer: %w", err)
	}

	t.APMTracer = tracer
	apm.DefaultTracer = t.APMTracer

	return nil
}

// Span is a wrapper around the backend span we use (currently APM spans and transactions),
// providing some other functionality also, like appsec logging errors.
type Span struct {
	span        *apm.Span
	transaction *apm.Transaction
}

// Close the current span.
// If it is called twice, it is a noop.
// It will nil-ify the current span, so it must not be
// used again.
func (s *Span) Close() {
	switch {
	case s.span != nil:
		s.span.End()
		s.span = nil
	case s.transaction != nil:
		s.transaction.End()
		s.transaction = nil
	}
}

// AddError attaches an error to this span, also logging it via appsec logging
func (s *Span) AddError(err error) {
	s.LogKV("error", err.Error())
	apmError := apm.DefaultTracer.NewError(err)
	switch {
	case s.span != nil:
		apmError.SetSpan(s.span)
		apmError.Send()
	case s.transaction != nil:
		apmError.SetTransaction(s.transaction)
		apmError.Send()
	}
	// TODO: Appsec logging
}

// LogKV Logs a keyvalue to the transaction context
func (s *Span) LogKV(key string, value interface{}) {
	switch {
	case s.span != nil:
		s.span.Context.SetLabel(key, value)
	case s.transaction != nil:
		s.transaction.Context.SetLabel(key, value)
	default:
		panic("nil span")
	}
}

// StartSpan starts a new span.
// The operationType is in the format of type.subtype.action.  For example: db.sql.query.
// It will use the span/transaction in the context as it's parent.  If no span/transaction
// exists in the context, a root transaction will be created.
func (t *Toolbox) StartSpan(ctx context.Context, operationName, operationType string) (*Span, context.Context) {
	// Check if the context has a span
	if span := apm.SpanFromContext(ctx); span != nil {
		span, ctx = apm.StartSpan(ctx, operationName, operationType)
		return &Span{span: span}, ctx
	}

	// Check if the context has a transaction
	if transaction := apm.TransactionFromContext(ctx); transaction != nil {
		// Create span off this transaction
		span := transaction.StartSpan(operationName, operationType, nil)
		ctx = apm.ContextWithSpan(ctx, span)
		return &Span{span: span}, ctx
	}

	// There is nothing in the context, start a new transaction
	transaction := t.APMTracer.StartTransaction(operationName, operationType)
	ctx = apm.ContextWithTransaction(ctx, transaction)
	return &Span{transaction: transaction}, ctx
}
