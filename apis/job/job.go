package main

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/opentracing/opentracing-go"
	"github.secureserver.net/threat/util/lambda/toolbox"
	_ "go.elastic.co/apm/module/apmlambda"
)

const (
	resourceName                  = "geoip"
	asherahQueueNameParameterName = "/ThreatTools/JobsQueue"
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
	t.LoadAWSSession(ctx, credentials.NewEnvCredentials(), "us-west-2")
	item, err := dynamoDBClient.GetItem(&dynamodb.GetItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"job_id": {S: aws.String(jobID)},
		},
		TableName: &t.JobDBTableName,
	})
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       "job_id not found, or an error encountered",
		}, nil
	}

	// For now just dump the raw item back to the user
	itemMarshalled, err := json.Marshal(item.Item)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       "error marshalling the item",
		}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       string(itemMarshalled),
	}, nil
}

// queueStructure is the structure inserted in to the queue to queue a job
type queueStructure struct {
	JobID           string                        `json:"jobID"`
	OriginalRequest events.APIGatewayProxyRequest `json:"original_request"`
}

// createJob creates a new job ID in dynamo DB and enqueue it in the queue
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
			Body:       "Error creating job",
		}, nil
	}
	span.Finish()

	// Add to queue
	span, ctx = opentracing.StartSpanFromContext(ctx, "SQSJob")

	// Marshal body
	requestMarshalled, err := json.Marshal(queueStructure{
		OriginalRequest: request,
		JobID:           jobID,
	})
	if err != nil {
		span.LogKV("error", err)
		span.Finish()
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       "error marshalling request",
		}, nil
	}
	requestMarshalledString := string(requestMarshalled)

	// Get the name of the SQS queue
	queueName, err := t.GetFromParameterStore(ctx, asherahQueueNameParameterName, false)
	if err != nil {
		span.LogKV("error", err)
		span.Finish()
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       "error finding queue name",
		}, nil
	}
	queueNameString := queueName.String()

	// Send the entire request marshalled along with the jobID
	sqsClient := sqs.New(t.AWSSession)
	_, err = sqsClient.SendMessage(&sqs.SendMessageInput{
		MessageBody: &requestMarshalledString,
		QueueUrl:    &queueNameString,
	})
	if err != nil {
		span.LogKV("error", err)
		span.Finish()
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       "error queueing job",
		}, nil
	}
	span.Finish()

	response := struct {
		JobID string `json:"job_id"`
	}{
		JobID: jobID,
	}
	responseBytes, _ := json.Marshal(response)
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       string(responseBytes),
	}, nil
}

func main() {
	lambda.Start(handler)
}
