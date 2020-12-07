// Package common provides some common data structures shared accross lambdas
package common

import "github.com/aws/aws-lambda-go/events"

// QueuedJob is the structure stored on the SQS queue to represent a queue job ready for processing
type QueuedJob struct {
	JobID           string                        `json:"jobID"`
	OriginalRequest events.APIGatewayProxyRequest `json:"original_request"`
}
