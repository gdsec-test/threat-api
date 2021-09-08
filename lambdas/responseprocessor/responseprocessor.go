package main

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/sirupsen/logrus"
	"github.com/vertoforce/regexgrouphelp"
	_ "go.elastic.co/apm/module/apmlambda"
)

var t *toolbox.Toolbox

var (
	// Regex to pull a lambda name from a ARN
	lambdaNameRegex = regexp.MustCompile(`\w+:\w+:\w+:.*?:.*?:.*?:(?P<lambdaName>.*?):`)
)

// handler is a lambda function that takes an array of SQS events, and processes every CompletedJob within that SQS event.
// So each event in is an array of SQS events, and each SQS event has an array of completed job data.
func handler(ctx context.Context, request events.SQSEvent) (string, error) {
	t = toolbox.GetToolbox()
	t.Logger.SetFormatter(&logrus.JSONFormatter{})

	var span *appsectracing.Span
	var span2 *appsectracing.Span
	// Process each SQS record
	for _, sqsRecord := range request.Records {
		span, ctx = t.TracerLogger.StartSpan(ctx, "ProcessSQSEvent", "jobs", "sqsevent", "process")

		// Try to unmarshal body
		completedLambdaData := LambdaDestination{}
		err := json.Unmarshal([]byte(sqsRecord.Body), &completedLambdaData)
		if err != nil {
			t.Logger.WithFields(logrus.Fields{"error": err, "body": sqsRecord.Body}).Error("Error unmarshaling completed job data")
			span.LogKV("error", err)
			span.End(ctx)
			continue
		}

		// Get lambda name from the event source ARN
		lambdaName := ""
		if groups, ok := regexgrouphelp.FindRegexGroups(lambdaNameRegex, completedLambdaData.RequestContext.FunctionArn)["lambdaName"]; ok && len(groups) > 0 {
			lambdaName = groups[0]
		}

		// Check if this was a failed execution
		if completedLambdaData.RequestContext.Condition != "Success" {
			// This lambda is actually a failure response
			span2, ctx = t.TracerLogger.StartSpan(ctx, "ProcessErroredJob", "jobs", "errors", "processjob")

			// When a job fails, it obviously does not submit the completed job data.
			// The completed job data includes the jobID, so we'll need another way to get the jobID.
			// Therefore, here we pull out the jobID from the original job SNS message
			var jobID string
			if len(completedLambdaData.RequestPayload.Records) > 0 {
				var jobSNSMessage common.JobSNSMessage
				json.Unmarshal([]byte(completedLambdaData.RequestPayload.Records[0].SNS.Message), &jobSNSMessage)
				jobID = jobSNSMessage.JobID
			}
			// log the module name and jobID with "ProcessErroredJob" for jobs that failed. The success ones are logged later anyway
			span2.LogKV("moduleName", lambdaName)
			span2.LogKV("jobID", jobID)

			t.Logger.WithFields(logrus.Fields{
				"eventSourceARN": sqsRecord.EventSourceARN,
				"functionARN":    completedLambdaData.RequestContext.FunctionArn,
				"jobID":          jobID,
				"moduleName":     lambdaName,
				"Condition":      completedLambdaData.RequestContext.Condition,
			}).Warn("This lambda response was a failed invocation.  We are replacing the data with error description")

			// Process this job, changing the response to contain the error AWS returned us
			err = processCompletedJob(ctx, common.CompletedJobData{
				// TODO: Update this to some other standard format?
				Response:   fmt.Sprintf(`[{"error":"%s"}]`, completedLambdaData.RequestContext.Condition),
				ModuleName: lambdaName,
				JobID:      jobID,
			})
			if err != nil {
				span2.LogKV("error", err)
				t.Logger.WithError(err).Error("Error processing response")
			}

			span2.End(ctx)
			span.End(ctx)
			continue
		}

		// Process every completed job from the passed in data
		for i, completedJob := range completedLambdaData.ResponsePayload {
			span2, ctx = t.TracerLogger.StartSpan(ctx, "ProcessCompletedJob", "job", "job", "processcompletedjob")
			// Set module name to be the lambda name if this job doesn't have a module name
			if completedJob.ModuleName == "" {
				// Get module name from ARN
				completedLambdaData.ResponsePayload[i].ModuleName = lambdaName
			}
			span2.LogKV("moduleName", completedJob.ModuleName)
			span2.LogKV("jobId", completedJob.JobID)

			t.Logger.WithFields(logrus.Fields{"moduleName": completedJob.ModuleName, "jobData": completedJob}).Info("Processing module response")

			// Convert blank responses to blank lists
			if completedJob.Response == "" {
				completedJob.Response = "[]"
			}

			err = processCompletedJob(ctx, completedJob)
			if err != nil {
				span2.LogKV("error", err)
				t.Logger.WithError(err).Error("Error processing response")
			}
			span2.End(ctx)
		}
		span.End(ctx)
	}

	return "", nil
}

// processCompleteJob takes the completed job data, encrypts the response, and adds it to the appropriate dynamoDB entry
func processCompletedJob(ctx context.Context, request common.CompletedJobData) error {
	if request.JobID == "" || request.ModuleName == "" {
		return fmt.Errorf("missing jobId or module name")
	}

	dynamodbClient := dynamodb.New(t.AWSSession)

	// Encrypt results with asherah
	var span *appsectracing.Span
	span, ctx = t.TracerLogger.StartSpan(ctx, "AsherahEncrypt", "asherah", "job", "encrypt")
	span.LogKV("jobID", request.JobID)
	encryptedData, err := t.Encrypt(ctx, request.JobID, []byte(request.Response))
	if err != nil {
		span.LogKV("error", err)
		span.End(ctx)
		return fmt.Errorf("error encrypting data: %w", err)
	}
	span.End(ctx)

	// Update the "responses" entry to contain a new map
	span, ctx = t.TracerLogger.StartSpan(ctx, "DynamoDBUpdate", "aws", "dynamodb", "updateItem")
	span.LogKV("jobID", request.JobID)
	defer span.End(ctx)

	update := expression.
		Set(expression.Name(fmt.Sprintf("responses.%s", request.ModuleName)), expression.Value(*encryptedData))
	expr, err := expression.NewBuilder().WithUpdate(update).Build()
	if err != nil {
		return fmt.Errorf("error creating update expression: %w", err)
	}
	_, err = dynamodbClient.UpdateItem(&dynamodb.UpdateItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"jobId": {S: &request.JobID},
		},
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		UpdateExpression:          expr.Update(),
		TableName:                 &t.JobDBTableName,
	})
	if err != nil {
		return err
	}

	return nil
}

func main() {
	lambda.Start(handler)
}
