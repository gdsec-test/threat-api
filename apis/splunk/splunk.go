package main

import (
	"context"
	"net/http"

	"github.com/vertoforce/go-splunk"
)

func (m *TriageModule) initClient(ctx context.Context) error {
	// Check if we already set up the client
	if m.splunkClient != nil {
		return nil
	}

	client, err := splunk.NewClient(ctx, m.SplunkUsername, m.SplunkPassword, &splunk.Config{HTTPClient: http.DefaultClient, BaseURL: m.SplunkBaseURL})
	if err != nil {
		return err
	}

	m.splunkClient = client

	return nil
}
