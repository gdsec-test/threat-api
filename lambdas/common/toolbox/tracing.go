package toolbox

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing/appseclogging"
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

// InitTracerLogger inits our APM tracer / App sec logger
func (t *Toolbox) InitTracerLogger(ctx context.Context) error {
	// Close the default tracer
	// See this for why we do this: https://pkg.go.dev/go.elastic.co/apm#NewTracerOptions
	apm.DefaultTracer.Close()

	// Set noop default tracer for now
	t.TracerLogger = appsectracing.NewTracerLogger(nil, nil)

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

	// Re-init the APM default tracer with this config
	transport, err := transport.InitDefault()
	if err != nil {
		return fmt.Errorf("error creating transport, probably a problem with the config: %w", err)
	}

	// Create the new apm tracer
	tracer, err := apm.NewTracerOptions(apm.TracerOptions{
		ServiceName: os.Getenv("AWS_LAMBDA_FUNCTION_NAME"), // TODO: How should we set this?
		Transport:   transport,
	})
	if err != nil {
		return fmt.Errorf("error creating tracer: %w", err)
	}

	// Set global APM tracer
	apm.DefaultTracer = tracer

	// Wrap the raw APM tracer in the appsectracing logger so we can create a TracerLogger object.
	// I know this sounds confusing.  Basically we just wrap the tracer in a library that lets us
	// handle tracing and logging in one place.
	appsecTracingTracer := appsectracing.NewAPMTracer(tracer)

	// Load appsec logger
	// TODO: Make this more generic?
	logger := appseclogging.NewLogger([]string{"threat-intel"}, map[string]string{"environment": "prod"})

	// Set toolbox appsec TracerLogger
	t.TracerLogger = appsectracing.NewTracerLogger(appsecTracingTracer, logger)

	return nil
}
