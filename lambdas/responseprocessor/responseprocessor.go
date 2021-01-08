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
	"github.com/opentracing/opentracing-go"
	"github.com/sirupsen/logrus"
	"github.com/vertoforce/regexgrouphelp"
	"github.secureserver.net/threat/util/lambda/toolbox"
	_ "go.elastic.co/apm/module/apmlambda"
)

var t *toolbox.Toolbox

var (
	lambdaNameRegex = regexp.MustCompile(`\w+:\w+:\w+:.*?:.*?:.*?:(?P<lambdaName>.*?):`)
)

// Lambda function to take a completed job data and insert it in to the database
func handler(ctx context.Context, request events.SQSEvent) (string, error) {
	t = toolbox.GetToolbox()
	t.Logger.SetFormatter(&logrus.JSONFormatter{})

	// TODO: Add tracing
	for _, sqsRecord := range request.Records {
		// Try to unmarshal body
		completedLambdaData := LambdaDestination{}
		err := json.Unmarshal([]byte(sqsRecord.Body), &completedLambdaData)
		if err != nil {
			t.Logger.WithFields(logrus.Fields{
				"error": err,
				"body":  string(sqsRecord.Body),
			}).Error("Error unmarshaling completed job data")
			continue
		}
		if completedLambdaData.ResponsePayload.ModuleName == "" {
			// Get module name from ARN
			if groups, ok := regexgrouphelp.FindRegexGroups(lambdaNameRegex, sqsRecord.EventSourceARN)["lambdaName"]; ok && len(groups) > 0 {
				completedLambdaData.ResponsePayload.ModuleName = groups[0]
			}
		}
		t.Logger.WithFields(logrus.Fields{"moduleName": completedLambdaData.ResponsePayload.ModuleName, "requestBody": sqsRecord.Body}).Info("Processing module response")

		_, err = processCompletedJob(ctx, completedLambdaData.ResponsePayload)
		if err != nil {
			t.Logger.WithError(err).Error("Error processing response")
		}
	}
	return "", nil
}

// processCompleteJob takes the completed job data, encrypts the response, and adds it to the appropriate dynamoDB entry
func processCompletedJob(ctx context.Context, request common.CompletedJobData) (string, error) {
	if request.JobID == "" || request.ModuleName == "" {
		return "", fmt.Errorf("missing jobID or module name")
	}

	dynamodbClient := dynamodb.New(t.AWSSession)

	// Encrypt results with asherah
	var span opentracing.Span
	span, ctx = opentracing.StartSpanFromContext(ctx, "AsherahEncrypt")
	encryptedData, err := t.Encrypt(ctx, request.JobID, []byte(request.Response))
	if err != nil {
		span.LogKV("error", err)
		span.Finish()
		return "", fmt.Errorf("error encrypting data: %w", err)
	}
	span.Finish()

	// Update the "responses" entry to contain a new map
	update := expression.
		Set(expression.Name(fmt.Sprintf("responses.%s", request.ModuleName)), expression.Value(*encryptedData))
	expr, err := expression.NewBuilder().WithUpdate(update).Build()
	if err != nil {
		return "", err
	}
	_, err = dynamodbClient.UpdateItem(&dynamodb.UpdateItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"job_id": {S: &request.JobID},
		},
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		UpdateExpression:          expr.Update(),
		TableName:                 &t.JobDBTableName,
	})
	if err != nil {
		return "", err
	}

	return "", nil
}

func main() {
	lambda.Start(handler)
}
