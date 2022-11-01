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
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/aws/aws-sdk-go/service/sns"
	. "github.com/aws/aws-sdk-go/service/sns"
	"github.com/gdcorp-golang/auth/gdtoken"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/smartystreets/goconvey/convey"
)

func TestPublishToSns(t *testing.T) {

	Convey("publishToSns", t, func() {
		tb := toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()
		snsClient := &SNS{}

		snsARN := "I_am_SNS_Topic_For_Submissions"
		jobID := "Cool job 45213"
		APIGatewayRequest := &events.APIGatewayProxyRequest{}
		var actualPublishInput *sns.PublishInput
		patches = append(patches, ApplyMethod(reflect.TypeOf(snsClient), "Publish",
			func(c *SNS, input *PublishInput) (*PublishOutput, error) {
				actualPublishInput = input
				return nil, nil
			}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("publish job to SNS successfully", func() {
			submissionMarshalled, _ := json.Marshal(common.JobSNSMessage{Submission: *APIGatewayRequest, JobID: jobID})
			submissionMarshalledString := string(submissionMarshalled)
			expectedPublishInput := &sns.PublishInput{
				Message:  &submissionMarshalledString,
				TopicArn: &snsARN,
			}
			actualError := publishToSns(tb, ctx1, *APIGatewayRequest, jobID, snsClient, snsARN)
			So(actualPublishInput, ShouldResemble, expectedPublishInput)
			So(actualError, ShouldResemble, nil)
		})

		Convey("should return error if cannot publish SNS Topic", func() {
			err := errors.New("I am error trying to publish to SNS")
			patches = append(patches, ApplyMethod(reflect.TypeOf(snsClient), "Publish",
				func(c *SNS, input *PublishInput) (*PublishOutput, error) {
					actualPublishInput = input
					return nil, err
				}))
			actualError := publishToSns(tb, ctx1, *APIGatewayRequest, jobID, snsClient, snsARN)
			So(actualError, ShouldResemble, err)
		})

	})
}

func TestCreateJob(t *testing.T) {

	Convey("createJob", t, func() {
		tb := toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()
		snsClient := &SNS{}

		patches = append(patches, ApplyFunc(sns.New,
			func(p client.ConfigProvider, cfgs ...*aws.Config) *SNS {
				return snsClient
			}))

		jobID := "Generatedjob 562432"
		APIGatewayRequest := &events.APIGatewayProxyRequest{
			Path: "Super cool path3ye435t",
		}
		patches = append(patches, ApplyMethod(reflect.TypeOf(tb), "GenerateJobID",
			func(t *Toolbox, ctx context.Context) string {
				return jobID
			}))

		jwtTokenString := "I am cool JWK secret token"
		patches = append(patches, ApplyFunc(toolbox.GetJWTFromRequest,
			func(request events.APIGatewayProxyRequest) string {
				return jwtTokenString
			}))

		jwtToken := &gdtoken.Token{}
		actualJWTToken := ""
		patches = append(patches, ApplyMethod(reflect.TypeOf(tb), "ValidateJWT",
			func(t *Toolbox, ctx context.Context, token string) (*gdtoken.Token, error) {
				actualJWTToken = token
				return jwtToken, nil
			}))

		originalRequester := ""
		patches = append(patches, ApplyFunc(toolbox.GetOriginalRequester,
			func(request events.APIGatewayProxyRequest) string {
				return originalRequester
			}))

		submittedModule := "I am cool64356"
		encryptedSubmission := &dynamodb.AttributeValue{
			S: &submittedModule,
		}
		patches = append(patches, ApplyFunc(encryptSubmission,
			func(box *toolbox.Toolbox, ctx context.Context, jobID string, body string) (*dynamodb.AttributeValue, error) {
				return encryptedSubmission, nil
			}))

		topicSubscriptions := 1
		topicArn := "I am cool ARN for SNS topic beryt2fgwe"
		patches = append(patches, ApplyFunc(countTopicSubscriptions,
			func(box *toolbox.Toolbox, ctx context.Context, snsClient *SNS) (int, string, error) {
				return topicSubscriptions, topicArn, nil
			}))

		actualRequester := ""
		patches = append(patches, ApplyFunc(storeRequestedModulesList,
			func(box *toolbox.Toolbox, ctx context.Context, jwt *gdtoken.Token, request *events.APIGatewayProxyRequest, originRequester string, jobID string, encryptedDataMarshalled *dynamodb.AttributeValue) error {
				actualRequester = originRequester
				return nil
			}))

		patches = append(patches, ApplyFunc(publishToSns,
			func(box *toolbox.Toolbox, ctx context.Context, request events.APIGatewayProxyRequest, jobID string, snsClient *sns.SNS, topicARN string) error {
				return nil
			}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should successfully create job", func() {
			response := struct {
				JobID string `json:"jobId"`
			}{JobID: jobID}
			responseBytes, _ := json.Marshal(response)
			expectedResponse := events.APIGatewayProxyResponse{
				StatusCode: 200,
				Body:       string(responseBytes),
			}
			actualResponse, _ := createJob(tb, ctx1, *APIGatewayRequest)
			So(actualResponse, ShouldResemble, expectedResponse)
		})

		Convey("should get JWT from actual response", func() {
			createJob(tb, ctx1, *APIGatewayRequest)
			So(actualJWTToken, ShouldResemble, jwtTokenString)
		})

		Convey("should get original requester if it is present", func() {
			originalRequester = "I am here 42314"
			createJob(tb, ctx1, *APIGatewayRequest)
			So(actualRequester, ShouldResemble, originalRequester)
		})

		Convey("should store module submission in DB properly", func() {
			actualJobID := ""
			var actualEncryptedDataMarshalled *dynamodb.AttributeValue
			actualFullJWTToken := &gdtoken.Token{}
			patches = append(patches, ApplyFunc(storeRequestedModulesList,
				func(box *toolbox.Toolbox, ctx context.Context, jwt *gdtoken.Token, request *events.APIGatewayProxyRequest, originRequester string, jobID string, encryptedDataMarshalled *dynamodb.AttributeValue) error {
					actualRequester = originRequester
					actualJobID = jobID
					actualEncryptedDataMarshalled = encryptedDataMarshalled
					actualFullJWTToken = jwt
					return nil
				}))
			createJob(tb, ctx1, *APIGatewayRequest)
			So(actualJobID, ShouldResemble, jobID)
			So(actualFullJWTToken, ShouldResemble, jwtToken)
			So(actualEncryptedDataMarshalled, ShouldResemble, encryptedSubmission)
		})

		Convey("should publish job in SNS properly", func() {
			actualJobID := ""
			actualTopicARN := ""
			patches = append(patches, ApplyFunc(publishToSns,
				func(box *toolbox.Toolbox, ctx context.Context, request events.APIGatewayProxyRequest, jobID string, snsClient *sns.SNS, topicARN string) error {
					actualJobID = jobID
					actualTopicARN = topicARN
					return nil
				}))
			createJob(tb, ctx1, *APIGatewayRequest)
			So(actualJobID, ShouldResemble, jobID)
			So(actualTopicARN, ShouldResemble, topicArn)
		})

		Convey("should return error if JWT validation failed", func() {
			err := errors.New("I am JWT Validation error")
			patches = append(patches, ApplyMethod(reflect.TypeOf(tb), "ValidateJWT",
				func(t *Toolbox, ctx context.Context, token string) (*gdtoken.Token, error) {
					return nil, err
				}))
			actualResponse, actualError := createJob(tb, ctx1, *APIGatewayRequest)
			So(actualError, ShouldResemble, err)
			So(actualResponse, ShouldResemble, events.APIGatewayProxyResponse{StatusCode: 401})
		})

		Convey("should return error if encrypt submission failed", func() {
			err := errors.New("I am encrypt submission error")
			patches = append(patches, ApplyFunc(encryptSubmission,
				func(box *toolbox.Toolbox, ctx context.Context, jobID string, body string) (*dynamodb.AttributeValue, error) {
					return nil, err
				}))
			actualResponse, actualError := createJob(tb, ctx1, *APIGatewayRequest)
			So(actualError, ShouldResemble, err)
			So(actualResponse, ShouldResemble, events.APIGatewayProxyResponse{StatusCode: 500})
		})

		Convey("should return error if count SNS Topic failed", func() {
			err := errors.New("I am error for count submission")
			patches = append(patches, ApplyFunc(countTopicSubscriptions,
				func(box *toolbox.Toolbox, ctx context.Context, snsClient *SNS) (int, string, error) {
					return 0, "", err
				}))
			actualResponse, actualError := createJob(tb, ctx1, *APIGatewayRequest)
			So(actualError, ShouldResemble, err)
			So(actualResponse, ShouldResemble, events.APIGatewayProxyResponse{StatusCode: 500})
		})

		Convey("should return error if job submissiob storage in DB failed", func() {
			err := errors.New("I am error for storing job in DB")
			patches = append(patches, ApplyFunc(storeRequestedModulesList,
				func(box *toolbox.Toolbox, ctx context.Context, jwt *gdtoken.Token, request *events.APIGatewayProxyRequest, originRequester string, jobID string, encryptedDataMarshalled *dynamodb.AttributeValue) error {
					return err
				}))
			actualResponse, actualError := createJob(tb, ctx1, *APIGatewayRequest)
			So(actualError, ShouldResemble, err)
			So(actualResponse, ShouldResemble, events.APIGatewayProxyResponse{StatusCode: 500})
		})

		Convey("should return error if Job topic publish ", func() {
			err := errors.New("I am error during SNS publish of job")
			patches = append(patches, ApplyFunc(publishToSns,
				func(box *toolbox.Toolbox, ctx context.Context, request events.APIGatewayProxyRequest, jobID string, snsClient *sns.SNS, topicARN string) error {
					return err
				}))
			actualResponse, actualError := createJob(tb, ctx1, *APIGatewayRequest)
			So(actualError, ShouldResemble, err)
			So(actualResponse, ShouldResemble, events.APIGatewayProxyResponse{StatusCode: 500})
		})

	})
}

func TestDeleteJob(t *testing.T) {

	Convey("deleteJob", t, func() {
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

		jobID := "Generatedjob 562432"
		APIGatewayRequest := &events.APIGatewayProxyRequest{
			Path: "Super cool path3ye435t",
		}

		jwtTokenString := "I am cool JWK secret token for delete jobs"
		patches = append(patches, ApplyFunc(toolbox.GetJWTFromRequest,
			func(request events.APIGatewayProxyRequest) string {
				return jwtTokenString
			}))

		jwtToken := &gdtoken.Token{
			BaseToken: gdtoken.BaseToken{
				AccountName: "Account Name fwer324",
			},
		}
		actualJWTToken := ""
		patches = append(patches, ApplyMethod(reflect.TypeOf(to), "ValidateJWT",
			func(t *Toolbox, ctx context.Context, token string) (*gdtoken.Token, error) {
				actualJWTToken = token
				return jwtToken, nil
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
		patches = append(patches, ApplyMethod(reflect.TypeOf(dynamoDBClient), "Scan",
			func(client *dynamodb.DynamoDB, input *dynamodb.ScanInput) (*dynamodb.ScanOutput, error) {
				return actualDynamodbScanOutput, nil
			}))

		actualDeleteItemOutput := &dynamodb.DeleteItemOutput{}
		patches = append(patches, ApplyMethod(reflect.TypeOf(dynamoDBClient), "DeleteItem",
			func(client *dynamodb.DynamoDB, input *dynamodb.DeleteItemInput) (*dynamodb.DeleteItemOutput, error) {
				return actualDeleteItemOutput, nil
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

		Convey("should successfully delete job", func() {
			expectedResponse := events.APIGatewayProxyResponse{StatusCode: http.StatusOK}
			actualResponse, _ := deleteJob(ctx1, *APIGatewayRequest, jobID)
			So(actualResponse, ShouldResemble, expectedResponse)
		})

		Convey("should get JWT from actual response", func() {
			deleteJob(ctx1, *APIGatewayRequest, jobID)
			So(actualJWTToken, ShouldResemble, jwtTokenString)
		})

		Convey("should return error if JWT validation failed", func() {
			err := errors.New("I am JWT Validation for deleted job error")
			patches = append(patches, ApplyMethod(reflect.TypeOf(to), "ValidateJWT",
				func(t *Toolbox, ctx context.Context, token string) (*gdtoken.Token, error) {
					return nil, err
				}))
			actualResponse, actualError := deleteJob(ctx1, *APIGatewayRequest, jobID)
			So(actualError, ShouldResemble, fmt.Errorf("error validating jwt: %w", err))
			So(actualResponse, ShouldResemble, events.APIGatewayProxyResponse{StatusCode: http.StatusUnauthorized})
		})

		Convey("should return error if cannot build expression for scanning in DynamoDB", func() {
			err := errors.New("I am build expression error for deleted job error")
			patches = append(patches, ApplyMethod(reflect.TypeOf(dynamodbBuilder), "Build",
				func(builder expression.Builder) (expression.Expression, error) {
					return actualExpression, err
				}))
			actualResponse, actualError := deleteJob(ctx1, *APIGatewayRequest, jobID)
			So(actualError, ShouldResemble, err)
			So(actualResponse, ShouldResemble, events.APIGatewayProxyResponse{StatusCode: 500})
		})

		Convey("should return error if scanning in DynamoDB failed", func() {
			err := errors.New("I am scanning error for deleted job error")
			patches = append(patches, ApplyMethod(reflect.TypeOf(dynamoDBClient), "Scan",
				func(client *dynamodb.DynamoDB, input *dynamodb.ScanInput) (*dynamodb.ScanOutput, error) {
					return nil, err
				}))
			actualResponse, actualError := deleteJob(ctx1, *APIGatewayRequest, jobID)
			So(actualError, ShouldResemble, fmt.Errorf("error searching for job id in db: %w", err))
			So(actualResponse, ShouldResemble, events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError})
		})

		Convey("should return forbidden status if scanning didnt find jobs in DB", func() {
			var foundJobsInDB int64
			foundJobsInDB = 0
			actualDynamodbScanOutput.Count = &foundJobsInDB
			actualResponse, _ := deleteJob(ctx1, *APIGatewayRequest, jobID)
			So(actualResponse, ShouldResemble, events.APIGatewayProxyResponse{StatusCode: http.StatusForbidden})
		})

		Convey("should return error if deleting job in DynamoDB failed", func() {
			err := errors.New("I am delete error for deleted job")
			patches = append(patches, ApplyMethod(reflect.TypeOf(dynamoDBClient), "DeleteItem",
				func(client *dynamodb.DynamoDB, input *dynamodb.DeleteItemInput) (*dynamodb.DeleteItemOutput, error) {
					return nil, err
				}))
			actualResponse, actualError := deleteJob(ctx1, *APIGatewayRequest, jobID)
			So(actualError, ShouldResemble, fmt.Errorf("error deleting job in DB: %w", err))
			So(actualResponse, ShouldResemble, events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError})
		})

	})
}
