package main

import (
	"context"
	"net/http"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	_ "go.elastic.co/apm/module/apmlambda"
)

const (
	resourceName             = "geoip"
	snsTopicARNParameterName = "/ThreatTools/JobRequests"
	// jobIDKey used in DB and API
	jobIDKey           = "jobId"
	usernameKey        = "username"
	originRequesterKey = "originrequester"
	// API Version and API path prefix
	version = "v1"
	vulnerabilitywatchLambdaName = "vulnerabilitywatch"
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
	// This helps standardize things across services
	to = toolbox.GetToolbox()
	defer to.Close(ctx)

	// Load dynamoDB
	dynamoDBClient = dynamodb.New(to.AWSSession)

	// Check if they are requesting their user's jobs
	path := strings.Trim(request.Path, "/")
	switch {
	case strings.HasPrefix(path, version+"/jobs"):
		switch request.HTTPMethod {
		case http.MethodPost:
			// They want to create a new job
			return createJob(to, ctx, request)
		case http.MethodGet:
			if jobID, ok := request.PathParameters[jobIDKey]; ok {
				// They are checking the status of a job
				return getJob(ctx, request, jobID)
			}
			// They are getting all their jobs
			return getJobs(ctx, request)
		case http.MethodDelete:
			if jobID, ok := request.PathParameters[jobIDKey]; ok {
				// They deleting this job
				return deleteJob(ctx, request, jobID)
			}
			return events.APIGatewayProxyResponse{StatusCode: http.StatusBadRequest, Body: "Missing jobId"}, nil
		default:
			return events.APIGatewayProxyResponse{StatusCode: http.StatusMethodNotAllowed}, nil
		}
	case strings.HasSuffix(path, version+"/classifications"):
		return classifyIOCs(ctx, request)
	case strings.HasSuffix(path, version+"/modules"):
		return GetModules(ctx, request)
	case strings.HasSuffix(path, version+"/vulnerability"):
		switch request.HTTPMethod {
		case http.MethodPost:
			return InvokeVulnerabilityService(ctx, request)
		default:
			return events.APIGatewayProxyResponse{StatusCode: http.StatusMethodNotAllowed}, nil
		}
	default:
		return events.APIGatewayProxyResponse{StatusCode: http.StatusNotFound}, nil
	}
}

func main() {
	lambda.Start(handler)
}
