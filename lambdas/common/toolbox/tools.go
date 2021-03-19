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
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/godaddy/asherah/go/appencryption"
	"github.com/sirupsen/logrus"
	"go.elastic.co/apm/module/apmhttp"
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

	// Tracing
	TracerLogger *appsectracing.TracerLogger

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

	// TODO: Use real context
	err := t.InitTracerLogger(context.Background())
	if err != nil {
		// panic(fmt.Errorf("error init tracer: %w", err))
		// TODO: Handle this error to let the caller know the tracing will not work
		fmt.Printf("WARN: Tracer not configured due to error: %s\n", err)
	}

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

	// Close appsec logger
	err = t.TracerLogger.Close(ctx)
	if err != nil {
		return fmt.Errorf("error closing tracer: %w", err)
	}

	return nil
}
