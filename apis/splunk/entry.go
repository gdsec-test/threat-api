package main

import (
	"context"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector"
)

func handler(ctx context.Context, request events.SNSEvent) ([]*common.CompletedJobData, error) {
	splunkModule := TriageModule{
		// TODO:
		SplunkUsername: "",
		SplunkPassword: "",
		SplunkBaseURL:  "",
	}
	return triagelegacyconnector.AWSToTriage(ctx, &splunkModule, request)
}

func main() {
	lambda.Start(handler)
}
