package toolbox

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/opentracing/opentracing-go"
	"go.elastic.co/apm"
	"go.elastic.co/apm/module/apmhttp"
	"go.elastic.co/apm/module/apmot"
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
		secret, err := t.GetFromCredentialsStore(ctx, key, nil)
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
		ServiceName: os.Getenv("ELASTIC_APM_SERVICE_NAME"), // TODO: How should we set this?
		Transport:   transport,
	})
	if err != nil {
		return fmt.Errorf("error creating tracer: %w", err)
	}

	// Wrap default APM Tracer with open tracing tracer
	t.APMTracer = tracer
	t.Tracer = apmot.New(apmot.WithTracer(t.APMTracer))
	opentracing.SetGlobalTracer(t.Tracer)

	return nil
}
