 package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"


	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	 "github.com/godaddy/asherah/go/appencryption"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	_ "go.elastic.co/apm/module/apmlambda"

	. "github.com/agiledragon/gomonkey/v2"
	. "github.com/smartystreets/goconvey/convey"
)

func TestProcessCompletedJob(t *testing.T) {
	Convey("ProcessCompletedJob", t, func() {
		patchUpdateDatabaseItem := ApplyFunc(UpdateDatabaseItem, func(dynamodbClient *dynamodb.DynamoDB, ctx context.Context, request common.CompletedJobData, encryptedData *appencryption.DataRowRecord) (err error) {
			return err
		})
		defer patchUpdateDatabaseItem.Reset()


		patchEncryptedResults := ApplyFunc(encrypt_results, func (ctx context.Context, request common.CompletedJobData) (encryptedData *appencryption.DataRowRecord, e error) {
			return nil, e
		})
		defer patchEncryptedResults.Reset()


		loggingSpan := &appsectracing.Span{}
		isErrorHappened := false
		// stub TracerLogger.StartSpan instance creation and point to it, cause it is needed to manipulate in tests
		var unmarshal_error error
		LogKVValues := []string{}
		patchLogKV := ApplyMethod(reflect.TypeOf(loggingSpan), "LogKV", func(_ *appsectracing.Span, key string, value interface{}) {
			fmt.Printf("Error happened %v", value)
			isErrorHappened = true
			if fmt.Sprintf("%T", value) == "*errors.errorString" ||  fmt.Sprintf("%T", value) == "*fmt.wrapError" {
				unmarshal_error = value.(error)
			} else {
				LogKVValues = append(LogKVValues,  value.(string))
			}
		})
		defer patchLogKV.Reset()
		fmt.Println(unmarshal_error)

		tb := toolbox.GetToolbox()
		dynamodbClient := dynamodb.New(tb.AWSSession)
		dynamodbNewPatches := ApplyFunc(dynamodb.New, func(p client.ConfigProvider, cfgs ...*aws.Config) *dynamodb.DynamoDB {
			return dynamodbClient
		})
		defer dynamodbNewPatches.Reset()


		ctx := context.Background()
		var completedJobData common.CompletedJobData
		completedJobDataJSON := `{
			"module_name": "nvd",
			"jobId" : "4245",
			"response": "fake_response"
		}`

		json.Unmarshal([]byte(completedJobDataJSON), &completedJobData)
		j, _ := json.MarshalIndent(completedJobData, "", "")
		fmt.Println(string(j))

		Convey("Should return proper processing of a completed job", func() {
			err := processCompletedJob(dynamodbClient, ctx, completedJobData)
			So(err, ShouldEqual, nil)
		})

		Convey("Should return error if job was not successfully updated", func() {
			expectedError := errors.New("Error from processcompletedjob")
			expectedError = fmt.Errorf("error updating database %w", expectedError)
			patch1 := ApplyFunc(UpdateDatabaseItem, func(dynamodbClient *dynamodb.DynamoDB, ctx context.Context, request common.CompletedJobData, encryptedData *appencryption.DataRowRecord) (err error) {
				return errors.New("Error from processcompletedjob")
			})
			defer patch1.Reset()
			fmt.Printf("Error happened %v", isErrorHappened)
			err := processCompletedJob(dynamodbClient, ctx, completedJobData)
			So(err, ShouldResemble, expectedError)
		})


		Convey("Should log job properly", func() {
			processCompletedJob(dynamodbClient, ctx, completedJobData)
			So(LogKVValues, ShouldResemble, []string{"4245"})
		})

		//TODO: Test for successful encryption
		// Convey("Should return error if job was not successfully encrypted", func() {}
	})
}
