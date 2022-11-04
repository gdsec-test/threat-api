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

	"github.com/godaddy/asherah/go/appencryption"
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
	span, _ := t.TracerLogger.StartSpan(ctx, "ResponseProcessorHandler", "responseprocessor", "", "UnmarshalingCompletedJobData")
	span2, _ := t.TracerLogger.StartSpan(ctx, "ResponseProcessorHandler", "responseprocessor", "", "ProcessingCompletedJobData")
	// Process each SQS record
	for _, sqsRecord := range request.Records {
		completedLambdaData, err := unmarshal_body(ctx, sqsRecord)
		if err != nil {
			t.Logger.WithFields(logrus.Fields{"error": err, "body": sqsRecord.Body}).Error("Error unmarshaling completed job data")
			span.LogKV("error", err)
			defer span.End(ctx)
			continue
		}
		// Get lambda name from the event source ARN
		lambdaName := ""
		if groups, ok := regexgrouphelp.FindRegexGroups(lambdaNameRegex, completedLambdaData.RequestContext.FunctionArn)["lambdaName"]; ok && len(groups) > 0 {
			lambdaName = groups[0]
		}

		// Check if this was a failed execution
		if completedLambdaData.RequestContext.Condition != "Success" {
			err = processFailedJob(ctx, sqsRecord, completedLambdaData, lambdaName)
			if err != nil {
				span2.LogKV("error", err)
				t.Logger.WithError(err).Error("Failed job error")
				continue
			}
		}
		//TODO: Maybe log error if there is one like with other functions?
		//Logic not there in initial response processor so unsure about this
		err = processSuccessfulJob(ctx, completedLambdaData, lambdaName)
		if err != nil {
			span2.LogKV("error", err)
			t.Logger.WithError(err).Error("Error processing a successful job")
			continue
		}
	}
	return "", nil
}

func unmarshal_body(ctx context.Context, sqsRecord events.SQSMessage) (LambdaDestination, error) {
	// Try to unmarshal body
	span, ctx := t.TracerLogger.StartSpan(ctx, "ProcessSQSEvent", "jobs", "sqsevent", "process")
	defer span.End(ctx)

	completedLambdaData := LambdaDestination{}
	err := json.Unmarshal([]byte(sqsRecord.Body), &completedLambdaData)
	return completedLambdaData, err
}

func processFailedJob(ctx context.Context, sqsRecord events.SQSMessage, completedLambdaData LambdaDestination, lambdaName string) (err error) {
	// This lambda is actually a failure response
	span2, ctx := t.TracerLogger.StartSpan(ctx, "ProcessErroredJob", "jobs", "errors", "processjob")
	defer span2.End(ctx)

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
	dynamodbClient := dynamodb.New(t.AWSSession)
	err = processCompletedJob(dynamodbClient, ctx, common.CompletedJobData{
		// TODO: Update this to some other standard format?
		Response:   fmt.Sprintf(`[{"error":"%s"}]`, completedLambdaData.RequestContext.Condition),
		ModuleName: lambdaName,
		JobID:      jobID,
	})

	return err
}

func processSuccessfulJob(ctx context.Context, completedLambdaData LambdaDestination, lambdaName string) (err error) {
	// Process every completed job from the passed in data
	for i, completedJob := range completedLambdaData.ResponsePayload {
		span2, ctx := t.TracerLogger.StartSpan(ctx, "ProcessSuccessfulJob", "job", "job", "processSuccessfulJob")
		defer span2.End(ctx)

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

		dynamodbClient := dynamodb.New(t.AWSSession)
		err = processCompletedJob(dynamodbClient, ctx, completedJob)
		if err != nil {
			span2.LogKV("error", err)
			t.Logger.WithError(err).Error("Error processing completed job")
		}
	}
	return err
}

// processCompleteJob takes the completed job data, encrypts the response, and adds it to the appropriate dynamoDB entry
func processCompletedJob(dynamodbClient *dynamodb.DynamoDB, ctx context.Context, request common.CompletedJobData) error {
	if request.JobID == "" || request.ModuleName == "" {
		return fmt.Errorf("missing jobId or module name")
	}

	span, ctx := t.TracerLogger.StartSpan(ctx, "ProcesscompletedJob", "aws", "processcompleted", "complete")
	span.LogKV("jobID", request.JobID)
	defer span.End(ctx)

	// Encrypt results with asherah
	encryptedData, e := encrypt_results(ctx, request)
	if e != nil {
		span.LogKV("error", e)
		t.Logger.WithError(e).Error("Error encrypting data")
	}

	err := UpdateDatabaseItem(dynamodbClient, ctx, request, encryptedData)
	if err != nil {
		span.LogKV("error", err)
		err = fmt.Errorf("error updating database %w", err)
	}

	return err
}

func encrypt_results(ctx context.Context, request common.CompletedJobData) (encryptedData *appencryption.DataRowRecord, e error) {
	span, ctx := t.TracerLogger.StartSpan(ctx, "AsherahEncrypt", "asherah", "job", "encrypt")
	span.LogKV("jobID", request.JobID)
	defer span.End(ctx)

	encryptedData, err := t.Encrypt(ctx, request.JobID, []byte(request.Response))
	if err != nil {
		span.LogKV("error", err)
		err = fmt.Errorf("error using t.encrypt: %w", err)
	}
	return encryptedData, err
}

func UpdateDatabaseItem(dynamodbClient *dynamodb.DynamoDB, ctx context.Context, request common.CompletedJobData, encryptedData *appencryption.DataRowRecord) (err error) {
	span, ctx := t.TracerLogger.StartSpan(ctx, "Updating Database", "aws update", "job", "update")
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
	return err
}

func main() {
	lambda.Start(handler)
}
