package main

import (
	"context"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/vertoforce/go-splunk"
)

// performSplunkSearch Performs the splunk search, waits for it to totally finish, and returns the results stream.
// It cancels and returns what it found so far if it runs too long
//
// This is mostly for long running searches that have a stats command at the end
func (m *TriageModule) performSplunkSearch(ctx context.Context, searchString string) (chan splunk.SearchResult, *splunk.Search, error) {
	var span opentracing.Span
	span, ctx = opentracing.StartSpanFromContext(ctx, "PerformSplunkSearch")
	defer span.Finish()

	search, err := m.splunkClient.CreateSearchJob(ctx, searchString, map[string]string{
		"earliest_time": splunk.FormatTime(time.Now().Add(-time.Hour * 24 * recentLoginsBackcheckDays)),
	})
	if err != nil {
		span.LogKV("error", "FailedLoginSplunkSearchError")
		span.LogKV("errorMessage", err.Error())
		return nil, nil, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, maxSplunkWaitTime)
	search.Wait(waitCtx)
	cancel()

	// Stop job no matter what
	// Use background content to guarantee we cancel the job even if the parent context is canceled
	waitCtx, cancel = context.WithTimeout(context.Background(), maxSplunkWaitTime)
	search.StopAndFinalize(waitCtx)
	cancel()

	results, err := search.GetResults(ctx)
	if err != nil {
		span.LogKV("error", "FailedLoginSplunkSearchError")
		span.LogKV("errorMessage", err.Error())
		return nil, nil, err
	}
	return results, search, nil
}
