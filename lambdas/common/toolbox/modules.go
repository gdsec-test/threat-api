package toolbox

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
	"github.com/opentracing/opentracing-go"
)

// GetModules gets the available modules and their supported IOC types
func (t *Toolbox) GetModules(ctx context.Context) (map[string]LambdaMetadata, error) {
	var span opentracing.Span
	span, ctx = opentracing.StartSpanFromContext(ctx, "GetModules")
	defer span.Finish()

	ssmClient := ssm.New(t.AWSSession)

	ret := map[string]LambdaMetadata{}
	err := ssmClient.GetParametersByPathPagesWithContext(ctx, &ssm.GetParametersByPathInput{
		Path: aws.String("/ThreatTools/Modules/"),
	}, func(output *ssm.GetParametersByPathOutput, b bool) bool {
		for _, parameter := range output.Parameters {
			// Unmarshal to structure
			metadata := LambdaMetadata{}
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
		return nil, fmt.Errorf("error fetching SSM parameters: %w", err)
	}

	return ret, nil
}

// LambdaMetadata is data stored in the parameter store about a specific lambda
type LambdaMetadata struct {
	SupportedIOCTypes []triage.IOCType `json:"supportedIOCTypes"`
	// AuthZ Actions that can be performed in this module
	Actions map[string]ActionSpecification `json:"actions"`
}

// ActionSpecification describes an action and what permissions are required to perform it
type ActionSpecification struct {
	RequiredADGroups []string `json:"requiredADGroups"`
}