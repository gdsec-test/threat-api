package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
)

// GetModules responds to a API gateway request to list the available modules and their metadata
func GetModules(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	modulesAndSupportedTypes, err := to.GetModules(ctx)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 500}, fmt.Errorf("error getting modules: %w", err)
	}
	marshalledData, err := json.Marshal(modulesAndSupportedTypes)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: "Error marshalling response"}, fmt.Errorf("error marshalling response: %w", err)
	}
	return events.APIGatewayProxyResponse{StatusCode: 200, Body: string(marshalledData)}, nil
}
