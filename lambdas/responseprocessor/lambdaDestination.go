package main

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
)

// LambdaDestination is the structure sent by a completed lambda
type LambdaDestination struct {
	Version        string `json:"version"`
	Timestamp      string `json:"timestamp"`
	RequestContext struct {
		RequestID              string `json:"requestId"`
		FunctionArn            string `json:"functionArn"`
		Condition              string `json:"condition"`
		ApproximateInvokeCount int64  `json:"approximateInvokeCount"`
	} `json:"requestContext"`
	RequestPayload  events.SNSEvent `json:"requestPayload"`
	ResponseContext struct {
		StatusCode      int64  `json:"statusCode"`
		ExecutedVersion string `json:"executedVersion"`
	} `json:"responseContext"`
	// Note that a completed job can contain data for multiple jobs, that is
	// why this is an array
	ResponsePayload CompletedJobDataList `json:"responsePayload"`
}

// CompletedJobDataList is a list of completed job datas, we define this extra structure
// to write our own unmarshaller
type CompletedJobDataList []common.CompletedJobData

// UnmarshalJSON unmarshals to the CompletedJobDataList, however if there is an error
// it ignores it.  This is for the case of a failed lambda (an array
// of completed job data is not returned, but we still want to process it)
func (l *CompletedJobDataList) UnmarshalJSON(data []byte) error {
	var completedJobs []common.CompletedJobData
	err := json.Unmarshal(data, &completedJobs)
	if err != nil {
		return nil
	}
	fmt.Println("Check on returned data")
	for i, job := range completedJobs {
		fmt.Println(i)
		fmt.Println(job.JobID)
		fmt.Println(job.Response)
		fmt.Println(job.ModuleName)
	}
	*l = CompletedJobDataList(completedJobs)
	return nil
}
