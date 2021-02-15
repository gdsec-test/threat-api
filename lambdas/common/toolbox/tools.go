package toolbox

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/godaddy/asherah/go/appencryption"
	"github.com/opentracing/opentracing-go"
	"github.com/sirupsen/logrus"
	"go.elastic.co/apm"
	"go.elastic.co/apm/module/apmhttp"
	"go.elastic.co/apm/module/apmot"
)

const (
	defaultTimeout             = time.Second * 5
	asherahKMSKeyParameterName = "/AdminParams/Team/KMSKey"
	ssoHostENVVar              = "SSO_HOST"
)

// Toolbox is standardized useful things
type Toolbox struct {
	Logger *logrus.Logger
	// Defaults to defaultSSOEndpoint
	SSOHostURL string `default:"sso.gdcorp.tools"`
	Tracer     opentracing.Tracer

	// This is the cached permissions structure to check against authorization requests
	permissionsModel PermissionsModel

	client *http.Client

	// AWS

	AWSSession *session.Session

	// Job DB
	JobDBTableName string `default:"jobs"`

	// Asherah

	AsherahDBTableName    string                            `default:"EncryptionKey"`
	AsherahSession        map[string]*appencryption.Session // Map of jobID to asherah sessions
	AsherahSessionFactory *appencryption.SessionFactory
	AsherahRegion         string `default:"us-west-2"` // The region that asherah will use for it's KMS (key management system)
	// The ARN to use for asherah's KMS if you want to override the default.
	// By default it will look up the asherahKMSKeyParameterName in SSM and use the _value_ of it as the ARN
	AsherahRegionARN string
}

// GetToolbox gets useful, standardized tools for processing with a lambda
func GetToolbox() *Toolbox {
	t := &Toolbox{
		Logger:         logrus.New(),
		Tracer:         apmot.New(), // Wrap default APM Tracer with open tracing tracer
		AsherahSession: map[string]*appencryption.Session{},
	}

	// Set any defaults
	typeOf := reflect.TypeOf(*t)
	valueOf := reflect.Indirect(reflect.ValueOf(t))
	for i := 0; i < typeOf.NumField(); i++ {
		if defaultValue := typeOf.Field(i).Tag.Get("default"); defaultValue != "" {
			valueOf.Field(i).SetString(defaultValue)
		}
	}

	// Load default aws session
	awsRegion := "us-west-2"
	if region := os.Getenv("AWS_REGION"); region != "" {
		awsRegion = region
	}
	t.LoadAWSSession(credentials.NewEnvCredentials(), awsRegion)

	if ssoHost := os.Getenv(ssoHostENVVar); ssoHost != "" {
		t.SSOHostURL = ssoHost
	}

	t.SetHTTPClient(&http.Client{Timeout: defaultTimeout})
	opentracing.SetGlobalTracer(t.Tracer)
	return t
}

// SetHTTPClient sets the http client of the toolbox, adding tracing to it as well
func (t *Toolbox) SetHTTPClient(client *http.Client) {
	if client == nil {
		client = http.DefaultClient
	}
	t.client = apmhttp.WrapClient(client)
}

// Close all our opened and live resources for soft shutdown
func (t *Toolbox) Close(ctx context.Context) error {
	err := t.CloseAsherahSessions(ctx)
	if err != nil {
		return fmt.Errorf("error closing asherah sessions: %w", err)
	}
	if t.AsherahSessionFactory != nil {
		err = t.AsherahSessionFactory.Close()
		if err != nil {
			return fmt.Errorf("error closing asherah session factory: %w", err)
		}
	}

	// Although we use open tracing as our generic tracing interface,
	// it's useful to call our specific APM flush functions here to make sure all spans are sent

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
	apm.DefaultTracer.Flush(abort)
	apm.DefaultTracer.SendMetrics(abort)
	apm.DefaultTracer.Close()
	// Tell our waiting thread that it doesn't need to wait anymore
	done <- struct{}{}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	return nil
}
