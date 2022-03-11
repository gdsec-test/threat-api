package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	"github.com/aws/aws-lambda-go/events"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
	. "github.com/smartystreets/goconvey/convey"
)

func TestClassifyIOCsCall(t *testing.T) {

	Convey("classifyIOCs", t, func() {
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()
		APIGatewayRequest := &events.APIGatewayProxyRequest{}

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		APICalls := map[triage.IOCType]string{
			triage.IPType:                `"27.41.67.138"`,
			triage.DomainType:            `"godaddy.com"`,
			triage.EmailType:             `"email@foo.com"`,
			triage.CVEType:               `"CVE-2021-0000"`,
			triage.CWEType:               `"CWE-000"`,
			triage.CAPECType:             `"CAPEC-000"`,
			triage.CPEType:               `"cpe:2.3:a:check_project:check:*:*:*:*:*:*:*:*"`,
			triage.URLType:               `"https://godaddy.com"`,
			triage.MD5Type:               `"5282ccccccccccccccccc11111111111"`,
			triage.SHA1Type:              `"66c80000000000000000000000aaaaaaaaaaaaaa"`,
			triage.SHA256Type:            `"84DDBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB000000000000000000000000"`,
			triage.SHA512Type:            `"891D11111111111111111111111AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA000000000000000000000000000000000000000000000000000000000"`,
			triage.AWSHostnameType:       `"ip-3456-3456.internal"`,
			triage.GoDaddyUsernameType:   `"user@godaddy.com"`,
			triage.GoDaddyHostnameType:   `"github.cloud.ppp.gdg"`,
			triage.MitreTacticType:       `"TA1122.001"`,
			triage.MitreTechniqueType:    `"t6014"`,
			triage.MitreSubTechniqueType: `"T6014.001"`,
			triage.MitreMitigationType:   `"M4002.003"`,
			triage.MitreMatrixType:       `"MA1057.003"`,
			triage.MitreGroupType:        `"G1057"`,
			triage.MitreSoftwareType:     `"S0066"`,
			triage.MitreDetectionType:    `"DS2014"`,
		}

		for _, IOCType := range triage.AllIOCTypes {
			APICallBody := APICalls[IOCType]
			if APICallBody != "" {
				Convey("should return " + fmt.Sprintf("%s", IOCType) + " as supported type for " + APICallBody, func() {
					APIGatewayRequest.Body = `{"iocs": [` + APICallBody + `]}`
					expectedList := `{"` + fmt.Sprintf("%s", IOCType) + `":[` + APICallBody + `]}`
					if IOCType == triage.GoDaddyUsernameType {
						expectedList = `{"` + fmt.Sprintf("%s", triage.EmailType) + `":[` + APICallBody + `],"` +
							fmt.Sprintf("%s", IOCType) + `":[` + strings.ReplaceAll(APICallBody, "@godaddy.com", "") + `]}`
					}
					expectedGetModulesResponse := events.APIGatewayProxyResponse{StatusCode: 200, Body: expectedList}
					actualGetModulesResponse, _ := classifyIOCs(ctx1, *APIGatewayRequest)
					So(actualGetModulesResponse, ShouldResemble, expectedGetModulesResponse)
				})
			} else {
				Convey("IOCType " + fmt.Sprintf("%s", IOCType) + " has no unit test written for it", func() {
					So(true, ShouldResemble, false)
				})
			}

		}

	})
}
