package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.secureserver.net/threat/util/lambda/toolbox"
	_ "go.elastic.co/apm/module/apmlambda"
)

const (
	snsTopicARNParameterName = "/ThreatTools/JobRequests"
)

// Lambda function to take a completed job data and insert it in to the database
func handler(ctx context.Context, request common.CompletedJobData) (string, error) {
	t := toolbox.GetToolbox()

	dynamodbClient := dynamodb.New(t.AWSSession)

	// Update the "results" entry to contain a new map
	update := expression.Set(expression.Name(fmt.Sprintf("results.%s", request.ModuleName)), expression.Value(request.Data))
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
