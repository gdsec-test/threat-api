// Package common provides some common data structures shared accross lambdas
package common

import "github.com/aws/aws-lambda-go/events"

// JobMessage is the structure sent via the SNS topic to represent a job ready for processing
type JobMessage struct {
	JobID           string                        `json:"jobID"`
	OriginalRequest events.APIGatewayProxyRequest `json:"original_request"`
}

// SQSCompletedJob is the raw structured passed from the SQS queue to be processes
type SQSCompletedJob struct {
	Records []Record `json:"Records"`
}

// Record is a SQS record
type Record struct {
	MessageID     string `json:"messageId"`
	ReceiptHandle string `json:"receiptHandle"`
	Body          string `json:"body"`
	Attributes    struct {
		ApproximateReceiveCount          string `json:"ApproximateReceiveCount"`
		SentTimestamp                    string `json:"SentTimestamp"`
		SenderID                         string `json:"SenderId"`
		ApproximateFirstReceiveTimestamp string `json:"ApproximateFirstReceiveTimestamp"`
	} `json:"attributes"`
	MessageAttributes interface{} `json:"messageAttributes"`
	Md5OfBody         string      `json:"md5OfBody"`
	EventSource       string      `json:"eventSource"`
	EventSourceARN    string      `json:"eventSourceARN"`
	AwsRegion         string      `json:"awsRegion"`
}

// CompletedJobData is a set of completed data from a job
type CompletedJobData struct {
	JobID      string `json:"job_id" dynamodbav:"job_id"`
	ModuleName string `json:"module_name" dynamodbav:"module_name"`
	Response   string `json:"response" dynamodbav:"response"`
}
