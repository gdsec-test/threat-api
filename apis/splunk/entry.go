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

var tb *toolbox.Toolbox
var jwt string

func handler(ctx context.Context, request events.SNSEvent) ([]*common.CompletedJobData, error) {
	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	SplunkCredentials, err := tb.GetFromCredentialsStore(ctx, "/ThreatTools/Integrations/splunk", nil)
	if err != nil {
		return nil, fmt.Errorf("error getting splunk credentials: %w", err)
	}
	if SplunkCredentials.SecretString == nil {
		return nil, fmt.Errorf("Invalid splunk credentials format in secrets manager")
	}
	secretStruct := struct {
		Username string
		Password string
		BaseURL  string `json:"BaseURL"`
	}{}
	err = json.Unmarshal([]byte(*SplunkCredentials.SecretString), &secretStruct)
	if err != nil {
		return nil, fmt.Errorf("invalid secret format for splunk credentials: %w", err)
	}

	splunkModule := TriageModule{
		SplunkUsername: secretStruct.Username,
		SplunkPassword: secretStruct.Password,
		SplunkBaseURL:  secretStruct.BaseURL,
	}
	return triagelegacyconnector.AWSToTriage(ctx, tb, &splunkModule, request)
}

func main() {
	lambda.Start(handler)
}
