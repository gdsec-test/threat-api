package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

// convertJobToSNSEvents converts a given job to a SNS event, panicing
// if there is any problem.  This is used for writing tests
func convertJobToSNSEvent(job common.JobSubmission) events.SNSEvent {
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

func TestHandler(t *testing.T) {
	jobEvent := convertJobToSNSEvent(common.JobSubmission{
		Modules: []string{"whois"},
		IOCs:    []string{"godaddy.com"},
		IOCType: string(triage.DomainType),
	})

	returnedJobData, err := handler(context.Background(), jobEvent)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(returnedJobData[0].Response)
}
