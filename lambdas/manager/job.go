package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/opentracing/opentracing-go"
	"github.secureserver.net/threat/util/lambda/toolbox"
	_ "go.elastic.co/apm/module/apmlambda"
)

const (
	resourceName             = "geoip"
	snsTopicARNParameterName = "/ThreatTools/JobRequests"
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
	jobID, ok := request.PathParameters["job_id"]
	if ok {
		// Assume they are checking on the status of this job
		return getJobStatus(ctx, jobID)
	}

	// Assume they want to create a new job
	return createJob(ctx, request)
}

// getJobStatus gets the job status from dynamoDB and send it as a response
func getJobStatus(ctx context.Context, jobID string) (events.APIGatewayProxyResponse, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "GetJobStatus")
	defer span.Finish()

	// Fetch job from database
	item, err := dynamoDBClient.GetItem(&dynamodb.GetItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"job_id": {S: aws.String(jobID)},
		},
		TableName: &t.JobDBTableName,
	})
	if err != nil {
		span.LogKV("error", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       ErrorResponse("error getting job from database").Marshal(),
		}, nil
	}

	if item.Item == nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 404,
			Body:       ErrorResponse("no job with that job_id in database").Marshal(),
		}, nil
	}

	// For now just dump the raw item back to the user
	response := &Response{JobID: jobID}
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

	// Store in database
	span, ctx = opentracing.StartSpanFromContext(ctx, "StoreJob")
	span.LogKV("job_id", jobID)
	_, err := dynamoDBClient.PutItem(&dynamodb.PutItemInput{
		Item: map[string]*dynamodb.AttributeValue{
			"job_id": {S: &jobID},
		},
		TableName: &t.JobDBTableName,
	})
	if err != nil {
		span.LogKV("error", err)
		span.Finish()
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       ErrorResponse("Error creating job").Marshal(),
		}, nil
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
		}, nil
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
		}, nil
	}
	span.Finish()

	response := &Response{JobID: jobID}
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       response.Marshal(),
	}, nil
}

func main() {
	lambda.Start(handler)
}
