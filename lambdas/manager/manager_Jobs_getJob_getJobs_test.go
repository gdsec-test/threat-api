package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	. "github.com/agiledragon/gomonkey/v2"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/smartystreets/goconvey/convey"
	"github.secureserver.net/auth-contrib/go-auth/gdtoken"
)

func TestGetJob(t *testing.T) {

	Convey("getJob", t, func() {
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()
		actualDynamoDBClient := &dynamodb.DynamoDB{}
		patches = append(patches, ApplyFunc(dynamodb.New,
			func(p client.ConfigProvider, cfgs ...*aws.Config) *dynamodb.DynamoDB {
				return actualDynamoDBClient
			}))

		to = toolbox.GetToolbox()
		dynamoDBClient = dynamodb.New(to.AWSSession)
		APIGatewayRequest := &events.APIGatewayProxyRequest{
			Path: "Super cool path3ye435t",
		}

		jobID := "job twer32t23s"
		jobStatus := JobInProgress
		jobPercentage := 47.45
		patches = append(patches, ApplyFunc(getJobProgress,
			func(ctx context.Context, jobEntry *common.JobDBEntry) (JobStatus, float64, error) {
				return jobStatus, jobPercentage, nil
			}))

		getItem := map[string]*dynamodb.AttributeValue{
			jobIDKey: {S: &jobID},
		}

		actualGetItemOutput := &dynamodb.GetItemOutput{
			Item: getItem,
		}
		patches = append(patches, ApplyMethod(reflect.TypeOf(dynamoDBClient), "GetItem",
			func(client *dynamodb.DynamoDB, input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
				return actualGetItemOutput, nil
			}))

		jobDB := &common.JobDBEntry{
			JobID: jobID,
		}
		patches = append(patches, ApplyMethod(reflect.TypeOf(jobDB), "Decrypt",
			func(job *common.JobDBEntry, ctx context.Context, box *toolbox.Toolbox) {
			}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
			dynamoDBClient = nil
			to = nil
		})

		Convey("should successfully delete job", func() {
			responseData, _ := json.Marshal(struct {
				common.JobDBEntry
				JobStatus     JobStatus `json:"jobStatus"`
				JobPercentage float64   `json:"jobPercentage"`
			}{
				JobDBEntry:    *jobDB,
				JobStatus:     jobStatus,
				JobPercentage: jobPercentage * 100,
			})
			expectedResponse := events.APIGatewayProxyResponse{StatusCode: 200, Body: string(responseData)}
			actualResponse, _ := getJob(ctx1, *APIGatewayRequest, jobID)
			So(actualResponse, ShouldResemble, expectedResponse)
		})

		Convey("should return error if JobID is not provided", func() {
			expectedResponse := events.APIGatewayProxyResponse{StatusCode: 400}
			actualResponse, _ := getJob(ctx1, *APIGatewayRequest, "")
			So(actualResponse, ShouldResemble, expectedResponse)
		})

		Convey("should return error if getting job from DB failed", func() {
			err := errors.New("I am getting job from DB error")
			patches = append(patches, ApplyMethod(reflect.TypeOf(dynamoDBClient), "GetItem",
				func(client *dynamodb.DynamoDB, input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
					return nil, err
				}))
			actualResponse, actualError := getJob(ctx1, *APIGatewayRequest, jobID)
			So(actualError, ShouldResemble, err)
			So(actualResponse, ShouldResemble, events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError})
		})

		Convey("should return error if getting job from DB found no jobs", func() {
			actualGetItemOutput.Item = nil
			actualResponse, _ := getJob(ctx1, *APIGatewayRequest, jobID)
			So(actualResponse, ShouldResemble, events.APIGatewayProxyResponse{StatusCode: 404})
		})

	})
}

func TestGetJobs(t *testing.T) {

	Convey("getJobs", t, func() {
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()
		actualDynamoDBClient := &dynamodb.DynamoDB{}
		patches = append(patches, ApplyFunc(dynamodb.New,
			func(p client.ConfigProvider, cfgs ...*aws.Config) *dynamodb.DynamoDB {
				return actualDynamoDBClient
			}))
		to = toolbox.GetToolbox()
		dynamoDBClient = dynamodb.New(to.AWSSession)

		jobID := "job 56243262 fgw"
		jobStatus := JobInProgress
		jobPercentage := 65.4
		patches = append(patches, ApplyFunc(getJobProgress,
			func(ctx context.Context, jobEntry *common.JobDBEntry) (JobStatus, float64, error) {
				return jobStatus, jobPercentage, nil
			}))

		APIGatewayRequest := &events.APIGatewayProxyRequest{
			Path: "Super cool pat2345frq34",
		}

		jwtTokenString := "I am cool JWK secret token345 gw4vw45"
		patches = append(patches, ApplyFunc(toolbox.GetJWTFromRequest,
			func(request events.APIGatewayProxyRequest) string {
				return jwtTokenString
			}))

		jwtToken := &gdtoken.Token{
			BaseToken: gdtoken.BaseToken{
				AccountName: "Account Name vaw45",
			},
		}

		actualJWTToken := ""
		patches = append(patches, ApplyMethod(reflect.TypeOf(to), "ValidateJWT",
			func(t *toolbox.Toolbox, ctx context.Context, token string) (*gdtoken.Token, error) {
				actualJWTToken = token
				return jwtToken, nil
			}))

		jobDB := &common.JobDBEntry{
			JobID: jobID,
		}
		patches = append(patches, ApplyMethod(reflect.TypeOf(jobDB), "Decrypt",
			func(job *common.JobDBEntry, ctx context.Context, box *toolbox.Toolbox) {
			}))

		var foundJobsInDB int64
		foundJobsInDB = 1

		foundItem := map[string]*dynamodb.AttributeValue{
			jobIDKey: {S: &jobID},
		}
		foundItems := []map[string]*dynamodb.AttributeValue{foundItem}
		actualDynamodbScanOutput := &dynamodb.ScanOutput{
			Count: &foundJobsInDB,
			Items: foundItems,
		}
		patches = append(patches, ApplyMethod(reflect.TypeOf(dynamoDBClient), "ScanPages",
			func(client *dynamodb.DynamoDB, input *dynamodb.ScanInput, fn func(*dynamodb.ScanOutput, bool) bool) error {
				fn(actualDynamodbScanOutput, false)
				return nil
			}))

		dynamodbBuilder := expression.Builder{}
		patches = append(patches, ApplyFunc(expression.NewBuilder,
			func() expression.Builder {
				return dynamodbBuilder
			}))

		actualExpression := expression.Expression{}
		patches = append(patches, ApplyMethod(reflect.TypeOf(dynamodbBuilder), "Build",
			func(builder expression.Builder) (expression.Expression, error) {
				return actualExpression, nil
			}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
			dynamoDBClient = nil
			to = nil
		})

		Convey("should successfully get all jobs", func() {
			jobDB := common.JobDBEntry{}
			dynamodbattribute.UnmarshalMap(foundItem, &jobDB)
			thisModuleResponse := ResponseData{
				JobDB:         jobDB,
				JobPercentage: jobPercentage * 100,
			}
			response := []ResponseData{}
			response = append(response, thisModuleResponse)
			responseBytes, _ := json.Marshal(response)
			expectedResponse := events.APIGatewayProxyResponse{
				StatusCode: 200,
				Body:       string(responseBytes),
			}
			actualResponse, _ := getJobs(ctx1, *APIGatewayRequest)
			So(actualResponse, ShouldResemble, expectedResponse)
		})

		Convey("should get JWT from actual response", func() {
			getJobs(ctx1, *APIGatewayRequest)
			So(actualJWTToken, ShouldResemble, jwtTokenString)
		})

		Convey("should return error if Scan pages expression cannot be built", func() {
			err := errors.New("I am scan pages expression built error")
			patches = append(patches, ApplyMethod(reflect.TypeOf(dynamodbBuilder), "Build",
				func(builder expression.Builder) (expression.Expression, error) {
					return actualExpression, err
				}))
			actualResponse, actualError := getJobs(ctx1, *APIGatewayRequest)
			So(actualError, ShouldResemble, err)
			So(actualResponse, ShouldResemble, events.APIGatewayProxyResponse{StatusCode: 500})
		})

		Convey("should return error if Scan pages cannot scan in DB", func() {
			err := errors.New("I am scan pages in DB error")
			patches = append(patches, ApplyMethod(reflect.TypeOf(dynamoDBClient), "ScanPages",
				func(client *dynamodb.DynamoDB, input *dynamodb.ScanInput, fn func(*dynamodb.ScanOutput, bool) bool) error {
					return err
				}))
			actualResponse, actualError := getJobs(ctx1, *APIGatewayRequest)
			So(actualError, ShouldResemble, fmt.Errorf("error getting jobs from database: %w", err))
			So(actualResponse, ShouldResemble, events.APIGatewayProxyResponse{StatusCode: 500})
		})

		Convey("should call progress with proper job entry found", func() {
			var expectedJobEntry *common.JobDBEntry
			patches = append(patches, ApplyFunc(getJobProgress,
				func(ctx context.Context, jobEntry *common.JobDBEntry) (JobStatus, float64, error) {
					expectedJobEntry = jobEntry
					return jobStatus, jobPercentage, nil
				}))
			getJobs(ctx1, *APIGatewayRequest)
			So(expectedJobEntry, ShouldResemble, jobDB)
		})
	})
}
