package main

import (
	"context"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector"
)

func handler(ctx context.Context, request events.SNSEvent) ([]*common.CompletedJobData, error) {
	// Super simple code to convert our interface to the legacy one
	tb := toolbox.GetToolbox()
	// and return the results
	virusTotalTriageModule := TriageModule{}
	return triagelegacyconnector.AWSToTriage(ctx, tb, &virusTotalTriageModule, request)
}

func main() {
	lambda.Start(handler)
}
