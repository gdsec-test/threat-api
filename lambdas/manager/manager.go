package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/godaddy/asherah/go/appencryption"
	"github.com/opentracing/opentracing-go"
	"github.secureserver.net/threat/util/lambda/toolbox"
	_ "go.elastic.co/apm/module/apmlambda"
)

const (
	resourceName             = "geoip"
	snsTopicARNParameterName = "/ThreatTools/JobRequests"
	jobIDKey                 = "job_id"
	usernameKey              = "username"
)

// Normall I wouldn't use global variables like this, but in such a small
// lambda function, this is simpler than passing in paramaters, and/or using closures
var t *toolbox.Toolbox
var dynamoDBClient *dynamodb.DynamoDB

// Lambda function to retrieve job status and output for ThreatTools API
func handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Get the toolbox
	// This helps standardize things accross services
	t = toolbox.GetToolbox()
	defer t.Close(ctx)

	// Load dynamoDB
	dynamoDBClient = dynamodb.New(t.AWSSession)

	// Check for jobID
	jobID, ok := request.PathParameters[jobIDKey]
	if ok {
		// Assume they are checking on the status of this job
		return getJobStatus(ctx, jobID)
	}

	// Check if they are requesting their user's jobs
	if strings.HasSuffix(strings.TrimRight(request.Path, "/"), "/jobs") {
		return getJobs(ctx, request)
	}

	// Assume they want to create a new job
	return createJob(ctx, request)
}

// createJob creates a new job ID in dynamo DB and sends it to the appropriate SNS topics
func createJob(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "CreateJob")
	defer span.Finish()

	// Generate job_id
	jobID := t.GenerateJobID(ctx)

	// Get username
	jwt, err := t.ValidateJWT(ctx, t.GetJWTFromRequest(request))
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 401}, err
	}
	span.LogKV("username", jwt.BaseToken.AccountName)

	// Encrypt request
	span, ctx = opentracing.StartSpanFromContext(ctx, "EncryptRequest")
	encryptedData, err := t.Encrypt(ctx, jobID, []byte(request.Body))
	if err != nil {
		span.LogKV("error", err)
		span.Finish()
		return events.APIGatewayProxyResponse{StatusCode: 500}, fmt.Errorf("error encrypting request: %w", err)
	}
	encryptedDataMarshalled, err := dynamodbattribute.Marshal(encryptedData)
	if err != nil {
		span.LogKV("error", err)
		span.Finish()
		return events.APIGatewayProxyResponse{StatusCode: 500}, fmt.Errorf("error marshalling encrypted data: %w", err)
	}
	span.Finish()

	// Store in database
	span, ctx = opentracing.StartSpanFromContext(ctx, "StoreJob")
	span.LogKV("job_id", jobID)
	_, err = dynamoDBClient.PutItem(&dynamodb.PutItemInput{
		Item: map[string]*dynamodb.AttributeValue{
			jobIDKey:    {S: &jobID},
			usernameKey: {S: &jwt.BaseToken.AccountName},
			"startTime": {N: aws.String(fmt.Sprintf("%d", time.Now().Unix()))},
			"ttl":       {N: aws.String(fmt.Sprintf("%d", time.Now().Add(time.Hour*24*30).Unix()))},
			"request":   encryptedDataMarshalled,
			"responses": {S: aws.String("")},
		},
		TableName: &t.JobDBTableName,
	})
	if err != nil {
		span.LogKV("error", err)
		span.Finish()
		return events.APIGatewayProxyResponse{StatusCode: 500}, err
	}
	span.Finish()

	// Send to SNS
	span, ctx = opentracing.StartSpanFromContext(ctx, "SendSNS")

	// Marshal body
	requestMarshalled, err := json.Marshal(common.JobMessage{OriginalRequest: request, JobID: jobID})
	if err != nil {
		span.LogKV("error", err)
		span.Finish()
		return events.APIGatewayProxyResponse{StatusCode: 500}, err
	}
	requestMarshalledString := string(requestMarshalled)

	// Get the SNS topic ARN
	topicARN, err := t.GetFromParameterStore(ctx, snsTopicARNParameterName, false)
	if err != nil || topicARN.Value == nil {
		span.LogKV("error", fmt.Errorf("error getting topicARN: %w", err))
		span.Finish()
		return events.APIGatewayProxyResponse{StatusCode: 500}, nil
	}

	// Send the entire request marshalled along with the jobID
	snsClient := sns.New(t.AWSSession)
	_, err = snsClient.Publish(&sns.PublishInput{
		Message:  &requestMarshalledString,
		TopicArn: aws.String(*topicARN.Value),
	})
	if err != nil {
		span.LogKV("error", err)
		span.Finish()
		return events.APIGatewayProxyResponse{StatusCode: 500}, err
	}
	span.Finish()

	response := struct {
		JobID string `json:"job_id"`
	}{JobID: jobID}
	responseBytes, _ := json.Marshal(response)
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       string(responseBytes),
	}, nil
}

// getJobStatus gets the job status from dynamoDB and send it as a response
func getJobStatus(ctx context.Context, jobID string) (events.APIGatewayProxyResponse, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "GetJobStatus")
	span.LogKV("job_id", jobID)
	defer span.Finish()

	if jobID == "" {
		return events.APIGatewayProxyResponse{StatusCode: 400}, nil
	}

	// Fetch job from database
	item, err := dynamoDBClient.GetItem(&dynamodb.GetItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			jobIDKey: {S: aws.String(jobID)},
		},
		TableName: &t.JobDBTableName,
	})
	if err != nil {
		span.LogKV("error", err)
		return events.APIGatewayProxyResponse{StatusCode: 500}, err
	}

	if item.Item == nil {
		return events.APIGatewayProxyResponse{StatusCode: 404}, nil
	}

	response := struct {
		Request            appencryption.DataRowRecord `dynamodbav:"request"`
		decryptedRequest   string
		Responses          interface{} `dynamodbav:"responses"`
		decryptedResponses map[string]interface{}
		StartTime          interface{} `dynamodbav:"startTime"`
	}{}
	dynamodbattribute.UnmarshalMap(item.Item, &response)

	// Asherah decrypt
	// TODO: Decrypt responses
	// span, ctx = opentracing.StartSpanFromContext(ctx, "DecryptResponses")
	// decryptedData, err := t.Dencrypt(ctx, jobID, response.Request)
	// if err == nil {
	// 	fmt.Println(decryptedData)
	// }
	// span.Finish()

	span, ctx = opentracing.StartSpanFromContext(ctx, "DecryptRequest")
	decryptedData, err := t.Dencrypt(ctx, jobID, response.Request)
	if err == nil {
		response.decryptedRequest = string(decryptedData)
	}

	// Marshal and reply
	responseData, _ := json.Marshal(struct {
		Request   string
		Responses map[string]interface{}
		StartTime interface{}
	}{
		Request:   response.decryptedRequest,
		Responses: response.decryptedResponses,
		StartTime: response.StartTime,
	})
	if err != nil {
		span.LogKV("error", err)
		return events.APIGatewayProxyResponse{StatusCode: 500}, nil
	}
	return events.APIGatewayProxyResponse{StatusCode: 200, Body: string(responseData)}, nil
}

func getJobs(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "GetUserJobs")
	defer span.Finish()

	jwt, err := t.ValidateJWT(ctx, t.GetJWTFromRequest(request))
	if err != nil {
		err = fmt.Errorf("error validating jwt: %w", err)
		span.LogKV("error", err)
		return events.APIGatewayProxyResponse{StatusCode: http.StatusUnauthorized}, err
	}

	// TODO: Extract username from request
	span.LogKV("username", jwt.BaseToken.AccountName)
	filter := expression.Name(usernameKey).Equal(expression.Value(jwt.BaseToken.AccountName))
	expr, err := expression.NewBuilder().WithFilter(filter).Build()
	if err != nil {
		span.LogKV("error", err)
		return events.APIGatewayProxyResponse{StatusCode: 500}, err
	}
	jobIDs := []string{}
	err = dynamoDBClient.ScanPages(&dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 &t.JobDBTableName,
	}, func(page *dynamodb.ScanOutput, lastPage bool) bool {
		for _, entry := range page.Items {
			if jobID, ok := entry[jobIDKey]; ok {
				jobIDs = append(jobIDs, *jobID.S)
			}
		}
		// Always get the next page
		return true
	})

	if err != nil {
		err = fmt.Errorf("error getting jobs from database: %w", err)
		span.LogKV("error", err)
		return events.APIGatewayProxyResponse{StatusCode: 500}, err
	}

	response, _ := json.Marshal(jobIDs)
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       string(response),
	}, err
}

func main() {
	lambda.Start(handler)
}
