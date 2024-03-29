package main

import (
	"context"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector"
)

var tb *toolbox.Toolbox

func handler(ctx context.Context, request events.SNSEvent) ([]*common.CompletedJobData, error) {
	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	// Super simple code to convert our interface to the legacy one
	// and return the results
	whoisTriageModule := TriageModule{}
	return triagelegacyconnector.AWSToTriage(ctx, tb, &whoisTriageModule, request)
}

func main() {
	lambda.Start(handler)
}
