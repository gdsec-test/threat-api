// Package common provides some common data structures shared accross lambdas
package common

import "github.com/aws/aws-lambda-go/events"

// JobMessage is the structure sent via the SNS topic to represent a job ready for processing
type JobMessage struct {
	JobID           string                        `json:"jobID"`
	OriginalRequest events.APIGatewayProxyRequest `json:"original_request"`
}
