package main

import (
	"context"
	"encoding/json"
	"reflect"
	"errors"
	"testing"


	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/godaddy/asherah/go/appencryption"
	_ "go.elastic.co/apm/module/apmlambda"

	. "github.com/agiledragon/gomonkey/v2"
	. "github.com/smartystreets/goconvey/convey"
)
func TestUpdateDatabaseIt(t *testing.T) {
	Convey("Update Database Item Testing", t, func() {
		tb := toolbox.GetToolbox()
		dynamodbClient := dynamodb.New(tb.AWSSession)

		patchUpdateIt := ApplyMethod(reflect.TypeOf(dynamodbClient), "UpdateItem", func(db *dynamodb.DynamoDB, input *dynamodb.UpdateItemInput) (output *dynamodb.UpdateItemOutput, err error) {
			return nil, err
		})
		defer patchUpdateIt.Reset()

		ctx := context.Background()

		var completedJobData common.CompletedJobData
		completedJobDataJSON := `{
			"module_name": "nvd",
			"jobId" : "4245",
			"response": "fake_response"
		}`
		json.Unmarshal([]byte(completedJobDataJSON), &completedJobData)

		var datarowdata appencryption.DataRowRecord
		datarowrecordJSON := `{
			Key: {
				Revoked: "revoked",
				-: "ID",
				Created: "createdate",
				Key: [1,2,3],
				ParentKeyMeta: {
					KeyId: "keyid",
					Created: 5678
				}
			},
			Data: [1,2,3,4]
		}`
		json.Unmarshal([]byte(datarowrecordJSON), &datarowdata)


		Convey("Should return properly update job", func() {
			err := UpdateDatabaseItem(dynamodbClient, ctx, completedJobData, &datarowdata)
			So(err, ShouldEqual, nil)
		})


  		Convey("Error condition for update item", func() {
			expected_err := errors.New("Error using AWS UpdateItem")
			patchUpdateIt := ApplyMethod(reflect.TypeOf(dynamodbClient), "UpdateItem", func(db *dynamodb.DynamoDB, input *dynamodb.UpdateItemInput) (output *dynamodb.UpdateItemOutput, err error) {
				return nil, expected_err
			})
			defer patchUpdateIt.Reset()

			update_error := UpdateDatabaseItem(dynamodbClient, ctx, completedJobData, &datarowdata)

			So(update_error, ShouldEqual, expected_err)

		})



	})
}
