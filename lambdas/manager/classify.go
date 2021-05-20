package main

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/gdcorp-infosec/go-ioc/ioc"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

// Regexes
var (
	// Regexes
	awsHostnameRegex     = regexp.MustCompile(`ip-(\d+-)+\d+.*internal`)
	godaddyHostnameRegex = regexp.MustCompile(`((\w|-)+\.?)+\.gdg`)

	mitreRegex = regexp.MustCompile("^(?P<concept>M(A)?|T(A)?|G|S)\\d{4}(\\.\\d{3})?$")
	//mitreRegex = regexp.MustCompile(`(?P<matrix>^MA\d+)|(?P<tactic>^TA\d+)|(?P<subtechnique>^T\d+[.]\d+)|(?P<technique>^T\d+)|(?P<mitigation>^M\d+)|(?P<group>^G\d+)|(?P<software>^S\d+)`)
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
		}
		// Try to parse it ourself if the triagetype is still unknown. If it's already assigned go with that as it's prior to this classification
		if triageType == triage.UnknownType {
			switch {
			case awsHostnameRegex.MatchString(iocInput):
				triageType = triage.AWSHostnameType
				// Use the raw input as the recognized input from the ioc library
				// will not be accurate
				triageContent = iocInput
			case mitreRegex.MatchString(iocInput) && len(iocInput) >= 5:
				regResult := mitreRegex.FindStringSubmatch(iocInput)
				if len(regResult) >= 2 {
					switch regResult[1] {
					case "MA":
						triageType = triage.MitreMatrixType
					case "TA":
						triageType = triage.MitreTacticType
					case "T":
						if regResult[4] != "" {
							triageType = triage.MitreSubTechniqueType
						} else {
							triageType = triage.MitreTechniqueType
						}
					case "M":
						triageType = triage.MitreMitigationType
					case "G":
						triageType = triage.MitreGroupType
					case "S":
						triageType = triage.MitreSoftwareType
					}
					triageContent = regResult[0]
				}
			case godaddyHostnameRegex.MatchString(iocInput):
				// TODO: Instead just look up using GoDaddy DNS server
				triageType = triage.HostnameType
				triageContent = iocInput
			}
		}

		if triageType == triage.UnknownType {
			iocsMap[triageType] = append(iocsMap[triageType], iocInput)
			continue
		}
		iocsMap[triageType] = append(iocsMap[triageType], triageContent)
	}

	return iocsMap
}
