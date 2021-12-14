package main

import (
    "context"
    "encoding/json"
    "testing"
	"errors"

	"github.com/aws/aws-lambda-go/events"
    _ "go.elastic.co/apm/module/apmlambda"

    . "github.com/agiledragon/gomonkey/v2"
    . "github.com/smartystreets/goconvey/convey"
)
func TestUnmarshal(t *testing.T) {
    Convey("Unmarshal Body ", t, func() {

		patchJSONUnmarshal := ApplyFunc(json.Unmarshal, func(data []byte, v interface{}) (err error) {
			return err
		})
		defer patchJSONUnmarshal.Reset()


		ctx := context.Background()

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

		Convey("Should return a properly unmarshaled body", func() {
			lambda, err := unmarshal_body(ctx, inputSQSMessage)
			print(lambda.Timestamp)
			So(err, ShouldBeNil)
		})

		Convey("Error from JSON unmarshal", func() {
			expected_err := errors.New("Error using JSON unmarshal")
			patchjsonUnmarshal := ApplyFunc(json.Unmarshal, func(data []byte, v interface{}) (err error) {
				return err
			})
			defer patchjsonUnmarshal.Reset()

			lambda, json_err := unmarshal_body(ctx, inputSQSMessage)
			print(lambda.Timestamp)

			So(json_err, ShouldEqual, expected_err)

		})



    })
}
