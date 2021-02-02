package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-util/lambda/toolbox"
)

// GetModules responds to a API gateway request to list the available modules and their metadata
func GetModules(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	modulesAndSupportedTypes, err := getModules(ctx, to)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 500}, fmt.Errorf("error getting modules: %w", err)
	}
	marshalledData, err := json.Marshal(modulesAndSupportedTypes)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: "Error marshalling response"}, fmt.Errorf("error marshalling response: %w", err)
	}
	return events.APIGatewayProxyResponse{StatusCode: 200, Body: string(marshalledData)}, nil
}

// getModules gets the available modules and their supported IOC types
func getModules(ctx context.Context, t *toolbox.Toolbox) (map[string]common.LambdaMetadata, error) {
	ssmClient := ssm.New(t.AWSSession)

	ret := map[string]common.LambdaMetadata{}
	err := ssmClient.GetParametersByPathPagesWithContext(ctx, &ssm.GetParametersByPathInput{
		Path: aws.String("/ThreatTools/Modules/"),
	}, func(output *ssm.GetParametersByPathOutput, b bool) bool {
		for _, parameter := range output.Parameters {
			// Unmarshal to structure
			metadata := common.LambdaMetadata{}
			err := json.Unmarshal([]byte(*parameter.Value), &metadata)
			if err != nil {
				continue
			}
			// Get the name after the last slash (lambda name)
			parameterName := strings.TrimRight(*parameter.Name, "/")
			if lastSlash := strings.LastIndex(parameterName, "/"); lastSlash != -1 {
				parameterName = parameterName[lastSlash+1:]
			}
			ret[parameterName] = metadata
		}
		return true
	})
	if err != nil {
		return nil, err
	}

	return ret, nil
}
