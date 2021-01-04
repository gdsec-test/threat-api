package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/opentracing/opentracing-go"
	"github.secureserver.net/threat/util/lambda/toolbox"
	_ "go.elastic.co/apm/module/apmlambda"
)

const (
	snsTopicARNParameterName = "/ThreatTools/JobRequests"
)

// Lambda function to take a completed job data and insert it in to the database
func handler(ctx context.Context, request common.CompletedJobData) (string, error) {
	if request.JobID == "" || request.ModuleName == "" {
		return "", fmt.Errorf("missing jobID or module name")
	}

	t := toolbox.GetToolbox()

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
