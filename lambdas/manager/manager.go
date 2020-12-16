package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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

// getJobStatus gets the job status from dynamoDB and send it as a response
func getJobStatus(ctx context.Context, jobID string) (events.APIGatewayProxyResponse, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "GetJobStatus")
	span.LogKV("job_id", jobID)
	defer span.Finish()

	if jobID == "" {
		return events.APIGatewayProxyResponse{StatusCode: 400, Body: ErrorResponse("Bad job_id").Marshal()}, nil
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
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       ErrorResponse("error getting job from database").Marshal(),
		}, err
	}

	if item.Item == nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 404,
			Body:       ErrorResponse("no job with that job id in database").Marshal(),
		}, nil
	}

	// Asherah decrypt
	span, ctx = opentracing.StartSpanFromContext(ctx, "AsherahDecrypt")
	asherahItem := appencryption.DataRowRecord{}
	dynamodbattribute.Unmarshal(item.Item["data"], &asherahItem)
	// TODO: Encrypt each item in map instead of data as a whole because each
	// lambda will be adding data to the map
	decryptedData, err := t.Dencrypt(ctx, jobID, asherahItem)
	if err != nil {
		span.LogKV("error", err)
		span.Finish()
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: ErrorResponse("error decrypting data").Marshal()}, nil
	}
	span.Finish()

	// For now just dump the raw item back to the user
	response := &Response{JobIDs: []string{jobID}, Data: decryptedData}
	err = dynamodbattribute.UnmarshalMap(item.Item, &response.Data)
	if err != nil {
		span.LogKV("error", err)
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: ErrorResponse("error marshalling response data").Marshal()}, nil
	}
	return events.APIGatewayProxyResponse{StatusCode: 200, Body: response.Marshal()}, nil
}

// createJob creates a new job ID in dynamo DB and sends it to the appropriate SNS topics
func createJob(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "CreateJob")
	defer span.Finish()

	// Generate job_id
	jobID := t.GenerateJobID(ctx)

	jwt, err := t.ValidateJWT(ctx, t.GetJWTFromRequest(request))
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 401, Body: ErrorResponse("bad jwt").Marshal()}, err
	}
	span.LogKV("username", jwt.BaseToken.AccountName)

	// Store in database
	span, ctx = opentracing.StartSpanFromContext(ctx, "StoreJob")
	span.LogKV("job_id", jobID)
	_, err = dynamoDBClient.PutItem(&dynamodb.PutItemInput{
		Item: map[string]*dynamodb.AttributeValue{
			jobIDKey:    {S: &jobID},
			usernameKey: {S: &jwt.BaseToken.AccountName},
		},
		TableName: &t.JobDBTableName,
	})
	if err != nil {
		span.LogKV("error", err)
		span.Finish()
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       ErrorResponse("Error creating job").Marshal(),
		}, err
	}
	span.Finish()

	// Send to SNS
	span, ctx = opentracing.StartSpanFromContext(ctx, "SendSNS")

	// Marshal body
	requestMarshalled, err := json.Marshal(common.JobMessage{
		OriginalRequest: request,
		JobID:           jobID,
	})
	if err != nil {
		span.LogKV("error", err)
		span.Finish()
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       ErrorResponse("error marshalling request").Marshal(),
		}, err
	}
	requestMarshalledString := string(requestMarshalled)

	// Get the SNS topic ARN
	topicARN, err := t.GetFromParameterStore(ctx, snsTopicARNParameterName, false)
	if err != nil || topicARN.Value == nil {
		span.LogKV("error", fmt.Errorf("error getting topicARN: %w", err))
		span.Finish()
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: "error finding sns topic arn"}, nil
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
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       ErrorResponse("error sending job to topic").Marshal(),
		}, err
	}
	span.Finish()

	response := &Response{JobIDs: []string{jobID}}
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       response.Marshal(),
	}, nil
}

func getJobs(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "GetUserJobs")
	defer span.Finish()

	jwt, err := t.ValidateJWT(ctx, t.GetJWTFromRequest(request))
	if err != nil {
		err = fmt.Errorf("error validating jwt: %w", err)
		span.LogKV("error", err)
		return events.APIGatewayProxyResponse{StatusCode: http.StatusUnauthorized, Body: ErrorResponse("bad JWT").Marshal()}, err
	}

	// TODO: Extract username from request
	span.LogKV("username", jwt.BaseToken.AccountName)
	filter := expression.Name(usernameKey).Equal(expression.Value(jwt.BaseToken.AccountName))
	expr, err := expression.NewBuilder().WithFilter(filter).Build()
	if err != nil {
		span.LogKV("error", err)
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: ErrorResponse("error searching database").Marshal()}, err
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
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: ErrorResponse("error getting jobs from database").Marshal()}, err
	}

	response := &Response{JobIDs: jobIDs}
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       response.Marshal(),
	}, err
}

func main() {
	lambda.Start(handler)
}
