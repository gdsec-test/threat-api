package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/gdcorp-infosec/go-ioc/ioc"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

// ClassifyRequest is the body of a request to classify IOCs
type ClassifyRequest struct {
	IOCs []string `json:"iocs"`
}

// classifyIOCs takes a AWS request and responds with the classified IOCs
func classifyIOCs(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Parse request
	classifyRequest := ClassifyRequest{}
	err := json.Unmarshal([]byte(request.Body), &classifyRequest)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 400, Body: "Bad request body"}, fmt.Errorf("error unmarshalling request: %w", err)
	}

	types := getIOCsTypes(classifyRequest.IOCs)

	bodyMarshalled, err := json.Marshal(types)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: "Error marshalling response"}, fmt.Errorf("error marshalling response: %w", err)
	}

	return events.APIGatewayProxyResponse{StatusCode: 200, Body: string(bodyMarshalled)}, nil
}

// getIOCsTypes Takes a list of IOCs and detects each type, grouping the results to a map
func getIOCsTypes(iocs []string) map[triage.IOCType][]string {
	iocsMap := map[triage.IOCType][]string{}
	for _, iocInput := range iocs {
		iocParsed := ioc.ParseIOC(iocInput)
		triageType := triage.UnknownType
		triageContent := iocParsed.IOC // Actual IOC we will send to be triaged
		// Convert from ioc library type to our triage type
		switch iocParsed.Type {
		case ioc.Domain:
			triageType = triage.DomainType
		case ioc.Email:
			triageType = triage.EmailType
			if strings.HasSuffix(iocInput, "@godaddy.com") {
				// This is also a godaddy username
				iocsMap[triage.GoDaddyUsernameType] = append(iocsMap[triage.GoDaddyUsernameType], strings.ReplaceAll(iocInput, "@godaddy.com", ""))
			}
		case ioc.URL:
			triageType = triage.URLType
		case ioc.IPv4:
			triageType = triage.IPType
		case ioc.IPv6:
			triageType = triage.IPType
		case ioc.CVE:
			triageType = triage.CVEType
		case ioc.SHA1:
			triageType = triage.SHA1Type
		case ioc.SHA256:
			triageType = triage.SHA256Type
		case ioc.SHA512:
			triageType = triage.SHA512Type
		case ioc.MD5:
			triageType = triage.MD5Type
		case ioc.CWE:
			triageType = triage.CWEType
		case ioc.CAPEC:
			triageType = triage.CAPECType
		case ioc.CPE:
			triageType = triage.CPEType
		case ioc.AWSHostName:
			triageType = triage.AWSHostnameType
		case ioc.GoDaddyHostName:
			triageType = triage.GoDaddyHostnameType
		case ioc.MitreMatrix:
			triageType = triage.MitreMatrixType
		case ioc.MitreTactic:
			triageType = triage.MitreTacticType
		case ioc.MitreTechnique:
			triageType = triage.MitreTechniqueType
		case ioc.MitreSubtechnique:
			triageType = triage.MitreSubTechniqueType
		case ioc.MitreMitigation:
			triageType = triage.MitreMitigationType
		case ioc.MitreGroup:
			triageType = triage.MitreGroupType
		case ioc.MitreSoftware:
			triageType = triage.MitreSoftwareType
		case ioc.MitreDetection:
			triageType = triage.MitreDetectionType
		}

		if triageType == triage.UnknownType {
			iocsMap[triageType] = append(iocsMap[triageType], iocInput)
			continue
		}
		iocsMap[triageType] = append(iocsMap[triageType], triageContent)
	}

	return iocsMap
}
