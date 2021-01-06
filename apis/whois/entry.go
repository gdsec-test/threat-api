package main

import (
	"context"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/gdcorp-infosec/threat-api/apis/triagec"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
)

func handler(ctx context.Context, request events.SNSEvent) (*common.CompletedJobData, error) {
	// Super simple code to convert our interface to the legacy one
	// and return the results
	whoisTriageModule := TriageModule{}
	return triagec.AWSToTriage(ctx, &whoisTriageModule, request.Records[0])
}

func main() {
	lambda.Start(handler)
}
