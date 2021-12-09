package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	_ "go.elastic.co/apm/module/apmlambda"

	. "github.com/agiledragon/gomonkey/v2"
	. "github.com/smartystreets/goconvey/convey"
)

func TestHandler(t *testing.T) {

	Convey("Response Processor Handler", t, func() {
		patchUnmarshalBody := ApplyFunc(unmarshal_body, func (ctx context.Context, sqsRecord events.SQSMessage) (LambdaDestination, error) {
			var result = LambdaDestination{}
			return result, nil
		})
		defer patchUnmarshalBody.Reset()

		patchProcessFailedJob := ApplyFunc(processFailedJob, func (ctx context.Context, sqsRecord events.SQSMessage, completedLambdaData LambdaDestination, lambdaName string) (err error) {
			return nil
		})
		defer patchProcessFailedJob.Reset()

		patchprocessSuccessfulJob := ApplyFunc(processSuccessfulJob, func (ctx context.Context, completedLambdaData LambdaDestination, lambdaName string) (err error){
			return nil
		})
		defer patchprocessSuccessfulJob.Reset()

		loggingSpan := &appsectracing.Span{}
		isErrorHappened := false
		patchesLoggingSpan := ApplyMethod(reflect.TypeOf(loggingSpan), "LogKV", func (_ *appsectracing.Span, key string, value interface{}) {
			fmt.Printf("Error happened %v", value)
			isErrorHappened = true
		})
		defer patchesLoggingSpan.Reset()

		ctx := context.Background()
		var inputRequestObj events.SQSEvent
		inputRequest := `{
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
		}`
		json.Unmarshal([]byte(inputRequest), &inputRequestObj)


		Convey("Should return proper successfull report", func() {
			handler(ctx, inputRequestObj)
			So(isErrorHappened, ShouldEqual, false)
		})


 		Convey("Error condition for unmarshal body", func() {
			var err error
			patchesUnmarshal_body := ApplyFunc(unmarshal_body, func (ctx context.Context, sqsRecord events.SQSMessage) (LambdaDestination, error) {
				var result = LambdaDestination{}
				err = errors.New("Could not unmarshal")
				return result, err
			})
			defer patchesUnmarshal_body.Reset()

			loggingSpan := &appsectracing.Span{}
			var unmarshal_error error
			// stub TracerLogger.StartSpan instance creation and point to it, cause it is needed to manipulate in tests
			loggingSpanPatches := ApplyMethod(reflect.TypeOf(loggingSpan), "LogKV", func (_ *appsectracing.Span, key string, value interface{}) {
				fmt.Printf("Error happened while unmarshaling%v", value)
				unmarshal_error = value.(error)
			})
			defer loggingSpanPatches.Reset()

			handler(ctx, inputRequestObj)
			So(err, ShouldEqual, unmarshal_error)

		})

		Convey("Error condition for successful job", func() {
			var err error
			patch1 := ApplyFunc(processSuccessfulJob, func (ctx context.Context, completedLambdaData LambdaDestination, lambdaName string) (err error){
				return err
			})
			defer patch1.Reset()


			loggingSpan := &appsectracing.Span{}
			var processj_error error
			// stub TracerLogger.StartSpan instance creation and point to it, cause it is needed to manipulate in tests
			loggingSpanPatches := ApplyMethod(reflect.TypeOf(loggingSpan), "LogKV", func (_ *appsectracing.Span, key string, value interface{}) {
				processj_error = value.(error)
			})
			defer loggingSpanPatches.Reset()

			handler(ctx, inputRequestObj)
			So(err, ShouldEqual, processj_error)

		})

		//TODO: Unit Test Expansion: Test for Process Failed Job
		//	Convey("Error condition for process failed job", func() {})

	})
}
