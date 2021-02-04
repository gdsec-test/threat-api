package main

import (
	"context"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/gdcorp-infosec/threat-util/lambda/toolbox"
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
var to *toolbox.Toolbox
var dynamoDBClient *dynamodb.DynamoDB

// JobStatus is the statuses a job can have
type JobStatus string

// Job statuses
const (
	JobInProgress JobStatus = "InProgress"
	JobIncomplete JobStatus = "Incomplete"
	JobCompleted  JobStatus = "Completed"
)

// Lambda function to retrieve job status and output for ThreatTools API
func handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Get the toolbox
	// This helps standardize things accross services
	to = toolbox.GetToolbox()
	defer to.Close(ctx)

	// Load dynamoDB
	dynamoDBClient = dynamodb.New(to.AWSSession)

	// Check for jobID to check status of job
	if jobID, ok := request.PathParameters[jobIDKey]; ok {
		// Assume they are checking on the status of this job
		return getJobStatus(ctx, jobID)
	}

	// Check if they are requesting their user's jobs
	path := strings.TrimRight(request.Path, "/")
	switch {
	case strings.HasSuffix(path, "/jobs"):
		return getJobs(ctx, request)
	case strings.HasSuffix(path, "/classify"):
		return classifyIOCs(ctx, request)
	case strings.HasSuffix(path, "/modules"):
		return GetModules(ctx, request)
	}

	// Assume they want to create a new job
	return createJob(ctx, request)
}

func main() {
	lambda.Start(handler)
}
