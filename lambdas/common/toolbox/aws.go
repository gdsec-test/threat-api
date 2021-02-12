package toolbox

import (
	"bytes"
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/opentracing/opentracing-go"
)

// ErrNoAWSSession Returns when you try to perform an AWS function without first calling LoadAWSSession
var ErrNoAWSSession = fmt.Errorf("no session in toolbox, call LoadAWSSession")

// LoadAWSSession loads an AWS session to the toolbox based on the passed in credentials.
// Note that this function will not validate the credentials, once you attempt an action it will
// alert you if you do not have permission.
func (t *Toolbox) LoadAWSSession(credentials *credentials.Credentials, region string) {
	t.AWSSession = session.New(aws.NewConfig().WithRegion(region).WithCredentials(credentials))
}

// GetFromParameterStore fetches a parameter from the AWS parameter store.
// If you call this function before calling LoadSession, it will return an error.
func (t *Toolbox) GetFromParameterStore(ctx context.Context, name string, withDecryption bool) (*ssm.Parameter, error) {
	if t.AWSSession == nil {
		return nil, ErrNoAWSSession
	}
	svc := ssm.New(t.AWSSession)

	GetAWSParameterSpan, _ := opentracing.StartSpanFromContext(ctx, "GetAWSParameter")
	output, err := svc.GetParameter(
		&ssm.GetParameterInput{
			Name:           aws.String(name),
			WithDecryption: aws.Bool(withDecryption),
		},
	)
	defer GetAWSParameterSpan.Finish()

	if err != nil {
		GetAWSParameterSpan.LogKV("error", err)
		return nil, err
	}

	return output.Parameter, nil
}

// GetFromCredentialsStore fetches a secret from AWS Secrets Manager.
// If you call this function before calling LoadSession, it will return an error.
func (t *Toolbox) GetFromCredentialsStore(ctx context.Context, secretID string, versionStage string) (*secretsmanager.GetSecretValueOutput, error) {
	if t.AWSSession == nil {
		return nil, ErrNoAWSSession
	}
	svc := secretsmanager.New(t.AWSSession)

	GetAWSSecretSpan, _ := opentracing.StartSpanFromContext(ctx, "GetAWSSecret")
	secret, err := svc.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretID),
		VersionStage: aws.String(versionStage),
	})
	defer GetAWSSecretSpan.Finish()

	if err != nil {
		GetAWSSecretSpan.LogKV("error", err)
		return nil, err
	}

	return secret, nil
}

// BuildUpdateItemInput Takes the provided structure and builds a UpdateItemInput for dyanmoDB.
// It will automatically build the update expression assuming you want to update each element passed in.
// NOTE: You will still need to set the table name and Key values
func BuildUpdateItemInput(keys []string, i interface{}) (*dynamodb.UpdateItemInput, error) {
	updateExpression := &bytes.Buffer{}
	updateExpression.WriteString("SET ")
	expressionAttributeValuesOriginal, err := dynamodbattribute.MarshalMap(i)
	if err != nil {
		return nil, err
	}
	expressionAttributeValues := map[string]*dynamodb.AttributeValue{}
	expressionAttributeNames := map[string]*string{}
keyValueLoop:
	for key := range expressionAttributeValuesOriginal {
		// Skip keys
		for _, k := range keys {
			if key == k {
				continue keyValueLoop
			}
		}

		// Pick new key with "#" in-front of it to avoid conflicts with dynamodb reserved words
		expressionAttributeNames["#"+key] = aws.String(key)
		// Set value in value array
		expressionAttributeValues[":"+key] = expressionAttributeValuesOriginal[key]

		// Add to update expression
		fmt.Fprintf(updateExpression, "#%s = :%s,", key, key)
	}

	// Remove last comma from UpdateExpression
	updateExpressionString := updateExpression.String()
	if len(updateExpressionString) > 0 {
		updateExpressionString = updateExpressionString[0 : len(updateExpressionString)-1]
	}

	return &dynamodb.UpdateItemInput{
		ExpressionAttributeValues: expressionAttributeValues,
		ExpressionAttributeNames:  expressionAttributeNames,
		UpdateExpression:          aws.String(updateExpressionString),
	}, nil
}
