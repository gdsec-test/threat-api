package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector"
)

const (
	cmapCredentialsStoreKey = toolbox.SecretsMangerSecretIDIntegrationsPrefix + "cmap"
)

var tb *toolbox.Toolbox

func handler(ctx context.Context, request events.SNSEvent) ([]*common.CompletedJobData, error) {
	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	cmapModule, err := initCMAPModule(ctx)
	if err != nil {
		return nil, fmt.Errorf("error creating module: %w", err)
	}
	return triagelegacyconnector.AWSToTriage(ctx, tb, cmapModule, request)
}

func initCMAPModule(ctx context.Context) (*TriageModule, error) {
	// Get CMAP cert and key from secret store
	secret, err := tb.GetFromCredentialsStore(ctx, cmapCredentialsStoreKey, nil)
	if err != nil {
		return nil, fmt.Errorf("error getting cmap secret: %w", err)
	}

	// Unmarshal
	cmapCreds := struct {
		CMAPCert string `json:"cmap_cert"`
		CMAPKey  string `json:"cmap_key"`
	}{}
	err = json.Unmarshal([]byte(*secret.SecretString), &cmapCreds)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling cmap creds: %w", err)
	}
	cmapTriageModule := &TriageModule{
		CMAPCert: cmapCreds.CMAPCert,
		CMAPKey:  cmapCreds.CMAPKey,
	}

	return cmapTriageModule, nil
}

func main() {
	lambda.Start(handler)
}
