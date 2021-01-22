package main

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
	"github.com/gdcorp-infosec/threat-util/lambda/toolbox"
)

// getModules gets the available modules and their supported IOC types
func getModules(ctx context.Context, t *toolbox.Toolbox) (map[string][]triage.IOCType, error) {
	ssmClient := ssm.New(t.AWSSession)

	ret := map[string][]triage.IOCType{}
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
			ret[parameterName] = metadata.SupportedIOCTypes
		}
		return true
	})
	if err != nil {
		return nil, err
	}

	return ret, nil
}
