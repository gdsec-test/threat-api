package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	. "github.com/agiledragon/gomonkey/v2"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	da "github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/sns"
	. "github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/godaddy/asherah/go/appencryption"
	. "github.com/smartystreets/goconvey/convey"
	"github.secureserver.net/auth-contrib/go-auth/gdtoken"
)

func TestEncryptSubmission(t *testing.T) {

	Convey("encryptSubmission", t, func() {
		tb := toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()
		submission := `{
			modules: ["apivoid"],
			iocs:    ["ioc73456"],
			iocType: "DOMAIN",
		}`
		jobID := "Id53456"

		encryptedData := &appencryption.DataRowRecord{
			Data: []byte(submission),
		}
		patches = append(patches, ApplyMethod(reflect.TypeOf(tb), "Encrypt",
			func(tbox *toolbox.Toolbox, ctx context.Context, jobID string, data []byte) (*appencryption.DataRowRecord, error) {
				return encryptedData, nil
			}))
		expectedData := &dynamodb.AttributeValue{}
		patches = append(patches, ApplyFunc(dynamodbattribute.Marshal,
			func(input interface{}) (*dynamodb.AttributeValue, error) {
				if reflect.DeepEqual(input, encryptedData) {
					return expectedData, nil
				}
				encodeValue, _ := da.NewEncoder().Encode(input)
				return encodeValue, nil
			}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("encrypt submission body properly", func() {
			actualEncryptedDataMarshalled, _ := encryptSubmission(tb, ctx1, jobID, submission)
			So(actualEncryptedDataMarshalled, ShouldResemble, expectedData)
		})

		Convey("should return error if encryption didn't go well", func() {
			err := errors.New("I am encryption error")
			patches = append(patches, ApplyMethod(reflect.TypeOf(tb), "Encrypt",
				func(tbox *toolbox.Toolbox, ctx context.Context, jobID string, data []byte) (*appencryption.DataRowRecord, error) {
					return nil, err
				}))
			_, actualError := encryptSubmission(tb, ctx1, jobID, submission)
			So(actualError, ShouldResemble, fmt.Errorf("error encrypting submission: %w", err))
		})

		Convey("should return error if dynamodb marshalling didn't go well", func() {
			err := errors.New("I am marshalling error")
			patches = append(patches, ApplyFunc(dynamodbattribute.Marshal,
				func(input interface{}) (*dynamodb.AttributeValue, error) {
					if reflect.DeepEqual(input, encryptedData) {
						return nil, err
					}
					encodeValue, _ := da.NewEncoder().Encode(input)
					return encodeValue, nil
				}))
			_, actualError := encryptSubmission(tb, ctx1, jobID, submission)
			So(actualError, ShouldResemble, fmt.Errorf("error marshalling encrypted data: %w", err))
		})

	})
}

func TestCountTopicSubscriptions(t *testing.T) {

	Convey("countTopicSubscriptions", t, func() {
		tb := toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()
		snsClient := &SNS{}
		patches = append(patches, ApplyFunc(sns.New,
			func(p client.ConfigProvider, cfgs ...*aws.Config) *SNS {
				return snsClient
			}))

		snsARN := "I_am_SNS_Topic_For_Submissions"
		topicARN := &ssm.Parameter{
			Value: &snsARN,
		}
		patches = append(patches, ApplyMethod(reflect.TypeOf(tb), "GetFromParameterStore",
			func(tbox *toolbox.Toolbox, ctx context.Context, name string, withDecryption bool) (*ssm.Parameter, error) {
				return topicARN, nil
			}))
		subscriptions := make([]*sns.Subscription, 14)
		subscriptionsOutput := &sns.ListSubscriptionsByTopicOutput{
			Subscriptions: subscriptions,
		}
		patches = append(patches, ApplyMethod(reflect.TypeOf(snsClient), "ListSubscriptionsByTopic",
			func(c *SNS, input *ListSubscriptionsByTopicInput) (*ListSubscriptionsByTopicOutput, error) {
				if input.TopicArn == topicARN.Value {
					return subscriptionsOutput, nil
				}
				return nil, nil
			}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("encrypt submission body properly", func() {
			totalModuleCount, topicARNValue, _ := countTopicSubscriptions(tb, ctx1, snsClient)
			So(totalModuleCount, ShouldResemble, len(subscriptions))
			So(&topicARNValue, ShouldResemble, topicARN.Value)
		})

		Convey("should return error if cannot get SNS Topic from Store", func() {
			err := errors.New("I am error to get SNS from store")
			patches = append(patches, ApplyMethod(reflect.TypeOf(tb), "GetFromParameterStore",
				func(tbox *toolbox.Toolbox, ctx context.Context, name string, withDecryption bool) (*ssm.Parameter, error) {
					return nil, err
				}))
			_, _, actualError := countTopicSubscriptions(tb, ctx1, snsClient)
			So(actualError, ShouldResemble, err)
		})

		Convey("should return error if error in subscriptions enumeration happens", func() {
			err := errors.New("I am error to get SNS subscriptions")
			patches = append(patches, ApplyMethod(reflect.TypeOf(snsClient), "ListSubscriptionsByTopic",
				func(c *SNS, input *ListSubscriptionsByTopicInput) (*ListSubscriptionsByTopicOutput, error) {
					if input.TopicArn == topicARN.Value {
						return nil, err
					}
					return nil, nil
				}))
			_, _, actualError := countTopicSubscriptions(tb, ctx1, snsClient)
			So(actualError, ShouldResemble, err)
		})

	})
}

func TestStoreRequestedModulesList(t *testing.T) {

	Convey("storeRequestedModulesList", t, func() {
		tb := toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()
		jwtToken := &gdtoken.Token{}
		dynamoDBClient := &dynamodb.DynamoDB{}
		dynamoDBRequest := &events.APIGatewayProxyRequest{}

		originRequester := "Some_requester"
		jobID := "ID_2345"
		submittedModule := "APIVOID"
		encryptedDataMarshalled := &dynamodb.AttributeValue{
			S: &submittedModule,
		}
		var actualItem map[string]*dynamodb.AttributeValue
		patches = append(patches, ApplyMethod(reflect.TypeOf(dynamoDBClient), "PutItem",
			func(c *dynamodb.DynamoDB, input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
				actualItem = input.Item
				return nil, nil
			}))
		jobSubmission := common.JobSubmission{
			Modules: []string{submittedModule},
		}
		patches = append(patches, ApplyFunc(common.GetJobSubmission,
			func(event events.APIGatewayProxyRequest) (common.JobSubmission, error) {
				return jobSubmission, nil
			}))

		requestedModules := &dynamodb.AttributeValue{
			SS: []*string{&submittedModule},
		}

		patches = append(patches, ApplyFunc(dynamodbattribute.Marshal,
			func(input interface{}) (*dynamodb.AttributeValue, error) {
				if reflect.DeepEqual(input, jobSubmission.Modules) {
					return requestedModules, nil
				}
				encodeValue, _ := da.NewEncoder().Encode(input)
				return encodeValue, nil
			}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("stores submitted job modules", func() {
			expectedItem := map[string]*dynamodb.AttributeValue{
				jobIDKey:           {S: &jobID},
				usernameKey:        {S: &jwtToken.BaseToken.AccountName},
				"startTime":        {N: aws.String(fmt.Sprintf("%d", time.Now().Unix()))},
				"ttl":              {N: aws.String(fmt.Sprintf("%d", time.Now().Add(time.Hour*24*30).Unix()))},
				"submission":       encryptedDataMarshalled,
				"responses":        {M: map[string]*dynamodb.AttributeValue{}},
				"requestedModules": requestedModules,
			}
			expectedItem[originRequesterKey] = &dynamodb.AttributeValue{S: &originRequester}
			err := storeRequestedModulesList(tb, ctx1, jwtToken, dynamoDBRequest, originRequester, jobID, encryptedDataMarshalled)
			So(err, ShouldResemble, nil)
			So(actualItem, ShouldResemble, expectedItem)
		})

		Convey("stores submitted job modules without original requestor if not provided", func() {
			expectedItem := map[string]*dynamodb.AttributeValue{
				jobIDKey:           {S: &jobID},
				usernameKey:        {S: &jwtToken.BaseToken.AccountName},
				"startTime":        {N: aws.String(fmt.Sprintf("%d", time.Now().Unix()))},
				"ttl":              {N: aws.String(fmt.Sprintf("%d", time.Now().Add(time.Hour*24*30).Unix()))},
				"submission":       encryptedDataMarshalled,
				"responses":        {M: map[string]*dynamodb.AttributeValue{}},
				"requestedModules": requestedModules,
			}
			err := storeRequestedModulesList(tb, ctx1, jwtToken, dynamoDBRequest, "", jobID, encryptedDataMarshalled)
			So(err, ShouldResemble, nil)
			So(actualItem, ShouldResemble, expectedItem)
		})

		Convey("returns error if cannot get job submission", func() {
			err := errors.New("Cannot marshal modules")
			patches = append(patches, ApplyFunc(dynamodbattribute.Marshal,
				func(input interface{}) (*dynamodb.AttributeValue, error) {
					if reflect.DeepEqual(input, jobSubmission.Modules) {
						return nil, err
					}
					encodeValue, _ := da.NewEncoder().Encode(input)
					return encodeValue, nil
				}))
			actualErr := storeRequestedModulesList(tb, ctx1, jwtToken, dynamoDBRequest, originRequester, jobID, encryptedDataMarshalled)
			So(actualErr, ShouldResemble, fmt.Errorf("error marshalling requestedModules: %w", err))
		})

		Convey("returns error if cannot marshal modules", func() {
			err := errors.New("Cannot marshal modules")
			patches = append(patches, ApplyFunc(common.GetJobSubmission,
				func(event events.APIGatewayProxyRequest) (common.JobSubmission, error) {
					return jobSubmission, err
				}))
			actualErr := storeRequestedModulesList(tb, ctx1, jwtToken, dynamoDBRequest, originRequester, jobID, encryptedDataMarshalled)
			So(actualErr, ShouldResemble, fmt.Errorf("error getting the jobSubmission: %w", err))
		})

		Convey("returns error if cannot save modules in DynamoDB", func() {
			err := errors.New("Cannot save modules in DynamoDB")
			patches = append(patches, ApplyMethod(reflect.TypeOf(dynamoDBClient), "PutItem",
			func(c *dynamodb.DynamoDB, input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
				actualItem = input.Item
				return nil, err
			}))
			actualErr := storeRequestedModulesList(tb, ctx1, jwtToken, dynamoDBRequest, originRequester, jobID, encryptedDataMarshalled)
			So(actualErr, ShouldResemble, err)
		})

	})
}
