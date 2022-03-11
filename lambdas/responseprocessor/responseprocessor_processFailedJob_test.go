
package main

import (
	"context"
	"encoding/json"
  	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	_ "go.elastic.co/apm/module/apmlambda"


	. "github.com/agiledragon/gomonkey/v2"
	. "github.com/smartystreets/goconvey/convey"
)

func TestProcessFailedJob(t *testing.T) {

	Convey("ProcessFailedJob", t, func() {

		patchpProcessCompletedJob := ApplyFunc(processCompletedJob, func(dynamodbClient *dynamodb.DynamoDB, ctx context.Context, request common.CompletedJobData) (err error) {
			return err
		})
		defer patchpProcessCompletedJob.Reset()

		loggingSpan := &appsectracing.Span{}
		isErrorHappened := false
		// stub TracerLogger.StartSpan instance creation and point to it, cause it is needed to manipulate in tests
		var unmarshal_error error
		LogKVValues := []string{}
		patchLogKV := ApplyMethod(reflect.TypeOf(loggingSpan), "LogKV", func(_ *appsectracing.Span, key string, value interface{}) {
			isErrorHappened = true
			if fmt.Sprintf("%T", value) == "*errors.errorString" {
				unmarshal_error = value.(error)
			} else {
				LogKVValues = append(LogKVValues,  value.(string))
			}
		})
		defer patchLogKV.Reset()

		tb := toolbox.GetToolbox()
		dynamodbClient := dynamodb.New(tb.AWSSession)
		dynamodbNewPatches := ApplyFunc(dynamodb.New, func(p client.ConfigProvider, cfgs ...*aws.Config) *dynamodb.DynamoDB {
			return dynamodbClient
		})
		defer dynamodbNewPatches.Reset()


		ctx := context.Background()
		var completedLambdaData LambdaDestination
		completedLambdaDataJSON := `{
			"version": "version2345",
			"timestamp": "timestamp3245",
			"requestContext": {
				"requestId": "requestId34",
				"functionArn": "functionArn234r",
				"condition": "condition234",
				"approximateInvokeCount": 234
			},
			"requestPayload": {
				"Records": [
					{
						"messageId": "messageId13456",
						"receiptHandle": "receiptHandle33458576",
						"body": "body23463y",
						"md5OfBody": "md5OfBody45yw4",
						"md5OfMessageAttributes": "md5OfMessageAttributes345w",
						"attributes": {"attributes234": "attributesValue234", "attributes345": "attributesValue5634"},
						"messageAttributes": {
							"record1": {
								"stringValue": "stringValue345234t",
								"binaryValue": [7],
								"stringListValues": ["stringListValues2", "stringListValues53"],
								"binaryListValues": [[5],[7]],
								"dataType": "dataType345"
							}
						},
						"eventSourceARN": "eventSourceARN35df",
						"eventSource": "eventSource345tw3",
						"awsRegion": "awsRegion45"
					}
				]
			},
			"responseContext": {
				"statusCode": 5423,
				"executedVersion": "executedVersion234"
			},
			"responsePayload": [
				{
					"module_name": "module_name234",
					"jobId": "jobId34234",
					"response": ""
				}
			]
		}`
		json.Unmarshal([]byte(completedLambdaDataJSON), &completedLambdaData)

		var inputSQSMessage events.SQSMessage
		inputRequest := `{
			"messageId": "messageId13456",
			"receiptHandle": "receiptHandle33458576",
			"body": "body23463y",
			"md5OfBody": "md5OfBody45yw4",
			"md5OfMessageAttributes": "md5OfMessageAttributes345w",
			"attributes": {"attributes234": "attributesValue234", "attributes345": "attributesValue5634"},
			"messageAttributes": {
				"record1": {
					"stringValue": "stringValue345234t",
					"binaryValue": [7],
					"stringListValues": ["stringListValues2", "stringListValues53"],
					"binaryListValues": [[5],[7]],
					"dataType": "dataType345"
				}
			},
			"eventSourceARN": "eventSourceARN35df",
			"eventSource": "eventSource345tw3",
			"awsRegion": "awsRegion45"
		}`
		json.Unmarshal([]byte(inputRequest), &inputSQSMessage)

		Convey("Should return proper processing of a failed job", func() {
			err := processFailedJob(ctx, inputSQSMessage, completedLambdaData, "nvd")
			fmt.Printf("Error happened %v", isErrorHappened)
			fmt.Printf("Error happened %v", unmarshal_error)
			So(err, ShouldBeNil)
		})

		Convey("Should return error if it is raised in completed job", func() {
			expectedError := errors.New("Error from completed job")
			patch1 := ApplyFunc(processCompletedJob, func(dynamodbClient *dynamodb.DynamoDB, ctx context.Context, request common.CompletedJobData) (err error) {
				return expectedError
			})
			defer patch1.Reset()
			fmt.Printf("Error happened %v", isErrorHappened)
			err := processFailedJob(ctx, inputSQSMessage, completedLambdaData, "nvd")
			So(err, ShouldResemble, expectedError)
		})


	})
}
