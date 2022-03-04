package appsectracing

import (
	"context"
	"fmt"
	"time"

	"go.elastic.co/apm"
)

// APMSpan is a wrapper around backend APM spans/transactions.
// Note that our tracer logger abstracts everything as a "span"
// but APM has both transactions and spans.  So this APMSpan could
// technically be a span or transaction under the hood, but we call
// it a span from higher up.
type APMSpan struct {
	startTime   time.Time
	span        *apm.Span
	transaction *apm.Transaction
}

type APMTracer struct {
	APMTracer *apm.Tracer
}

func NewAPMTracer(apmTracer *apm.Tracer) *APMTracer {
	return &APMTracer{APMTracer: apmTracer}
}

// StartSpan starts a new span.
// The operationType is in the format of type.subtype.action.  For example: db.sql.query.
// It will use the span/transaction in the context as it's parent.  If no span/transaction
// exists in the context, a root transaction will be created.
func (a *APMTracer) StartSpan(ctx context.Context, operationName, opType, operationSubType, operationAction string) (TracingSpan, context.Context) {
	// combine operation type, sub type, and action to APM specific formation
	operationType := fmt.Sprintf("%s.%s.%s", opType, operationSubType, operationAction)

	// Check if the context has a span
	if span := apm.SpanFromContext(ctx); span != nil {
		// TODO: Start off a.APMTracer

		// Only use this span if it hasn't been completed yet.
		// If spanData is nil, it means the span is already done.  So we'll
		// just start a new one
		if span.SpanData != nil {
			startTime := time.Now()
			span, ctx = apm.StartSpanOptions(ctx, operationName, operationType, apm.SpanOptions{Start: startTime})
			return &APMSpan{startTime: startTime, span: span}, ctx
		}
	}

	// Check if the context has a transaction
	if transaction := apm.TransactionFromContext(ctx); transaction != nil {
		// Create span off this transaction
		// Only use this transaction if it hasn't been completed yet.
		// If transactionData is nil, it means the transaction is already done.  So we'll
		// just start a new one
		if transaction.TransactionData != nil {
			startTime := time.Now()
			span := transaction.StartSpanOptions(operationName, operationType, apm.SpanOptions{Start: startTime})
			ctx = apm.ContextWithSpan(ctx, span)
			return &APMSpan{startTime: startTime, span: span}, ctx
		}
	}

	// There is nothing in the context, start a new transaction
	startTime := time.Now()
	transaction := a.APMTracer.StartTransactionOptions(operationName, operationType, apm.TransactionOptions{Start: startTime})
	ctx = apm.ContextWithTransaction(ctx, transaction)
	span, _ := apm.StartSpanOptions(ctx, operationName, operationType, apm.SpanOptions{Start: startTime})
	return &APMSpan{startTime: startTime, transaction: transaction, span: span}, ctx
}

func (a *APMTracer) Close(ctx context.Context) error {
	// Create abort channel based on the context
	abort := make(chan struct{})
	done := make(chan struct{})
	// Create a thread to wait on the context being canceled to signal the abort channel
	go func() {
		select {
		case <-ctx.Done():
			// Keep signalling the abort channel until done is signaled
			// This will cancel anything reading from the abort channel until we are told to stop
			for {
				select {
				case abort <- struct{}{}:
				case <-done:
					return
				}
			}
		case <-done:
			// The tracer functions completed successfully, stop waiting on this context
			return
		}
	}()
	a.APMTracer.Flush(abort)
	a.APMTracer.SendMetrics(abort)
	a.APMTracer.Close()
	// Tell our waiting thread that it doesn't need to wait anymore
	done <- struct{}{}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	return nil
}

// End the current span.
// If it is called twice, it is a noop.
// It will nil-ify the current span, so the span must not be
// used again.
func (s *APMSpan) End(ctx context.Context) {
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
func (s *APMSpan) AddError(err error) {
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

}

// LogKV Logs a keyvalue to the span/transaction context
func (s *APMSpan) LogKV(key string, value interface{}) {
	switch {
	case s.span != nil:
		s.span.Context.SetLabel(key, value)
	case s.transaction != nil:
		s.transaction.Context.SetLabel(key, value)
	default:
		panic("nil span")
	}
}

// GetStartTime of this span
func (s *APMSpan) GetStartTime() time.Time {
	return s.startTime
}

// GetEndTime of this span
func (s *APMSpan) GetEndTime() time.Time {
	switch {
	case s.span != nil:
		if s.span.Duration == -1 {
			// Still ongoing, return time.Zero
			return time.Time{}
		}
		return s.startTime.Add(s.span.Duration)
	case s.transaction != nil:
		if s.transaction.Duration == -1 {
			// Still ongoing, return time.Zero
			return time.Time{}
		}
		return s.startTime.Add(s.transaction.Duration)
	}
	return time.Time{}
}
