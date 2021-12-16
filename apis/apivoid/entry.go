package main

import (
	"context"
	"encoding/json"

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

	apivoidTriageModule := TriageModule{}
	return triagelegacyconnector.AWSToTriage(ctx, tb, &apivoidTriageModule, request)
}

func main() {
	lambda.Start(handler)
}

func convertJobToSNSEvent(job common.JobSubmission) events.SNSEvent {
	tb = toolbox.GetToolbox()
	defer tb.Close(context.Background())

	jobBodyMarshalled, err := json.Marshal(job)
	if err != nil {
		panic(err)
	}

	jobSNS := common.JobSNSMessage{
		JobID: "test",
		Submission: events.APIGatewayProxyRequest{
			Body: string(jobBodyMarshalled),
		},
	}

	jobSNSMarshalled, err := json.Marshal(jobSNS)
	if err != nil {
		panic(err)
	}

	return events.SNSEvent{
		Records: []events.SNSEventRecord{
			{SNS: events.SNSEntity{
				Message: string(jobSNSMarshalled),
			}},
		},
	}
}
