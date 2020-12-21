// Package common provides some common data structures shared accross lambdas
package common

import "github.com/aws/aws-lambda-go/events"

// JobMessage is the structure sent via the SNS topic to represent a job ready for processing
type JobMessage struct {
	JobID           string                        `json:"jobID"`
	OriginalRequest events.APIGatewayProxyRequest `json:"original_request"`
}

// CompletedJobData is a set of completed data from a job
type CompletedJobData struct {
	JobID      string `json:"job_id" dynamodbav:"job_id"`
	ModuleName string `json:"module_name" dynamodbav:"module_name"`
	Response   string `json:"response" dynamodbav:"response"`
}
