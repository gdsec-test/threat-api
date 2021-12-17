package common

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-lambda-go/events"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

// RunModules to test module from it's main method, see code example below
/* func main() {
	//lambda.Start(handler)
	common.RunModules([]string{"apivoid"}, []string{"google.com"}, triage.DomainType, handler)
}*/
func RunModules(modulesList []string, IOCs []string, iocType triage.IOCType,
	handler func(ctx context.Context, request events.SNSEvent) ([]*CompletedJobData, error)) ([]*CompletedJobData, error) {
	job := JobSubmission{
		Modules: modulesList,
		IOCs:    IOCs,
		IOCType: string(iocType),
	}

	jobBodyMarshalled, err := json.Marshal(job)
	if err != nil {
		panic(err)
	}

	jobSNS := JobSNSMessage{
		JobID: "test",
		Submission: events.APIGatewayProxyRequest{
			Body: string(jobBodyMarshalled),
		},
	}

	jobSNSMarshalled, err := json.Marshal(jobSNS)
	if err != nil {
		panic(err)
	}

	snsJobEventEvent := events.SNSEvent{
		Records: []events.SNSEventRecord{
			{SNS: events.SNSEntity{
				Message: string(jobSNSMarshalled),
			}},
		},
	}
	return handler(context.Background(), snsJobEventEvent)
}
