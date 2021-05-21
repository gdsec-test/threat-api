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

	geoIPTriageModule := TriageModule{}
	return triagelegacyconnector.AWSToTriage(ctx, tb, &geoIPTriageModule, request)
}

func main() {
	lambda.Start(handler)
}
