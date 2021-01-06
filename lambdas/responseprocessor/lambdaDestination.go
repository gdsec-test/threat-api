package main

import (
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
	ResponsePayload common.CompletedJobData `json:"responsePayload"`
}
