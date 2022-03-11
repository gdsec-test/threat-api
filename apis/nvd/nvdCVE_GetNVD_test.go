package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	. "net/http"
	"net/url"
	"path"
	"reflect"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	nvd "github.com/gdcorp-infosec/threat-api/apis/nvd/nvdLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/smartystreets/goconvey/convey"
)

func TestGetNVD(t *testing.T) {

	Convey("GetNVD", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()
		actualURL := ""
		requestMethod := ""
		patches = append(patches, ApplyFunc(http.NewRequestWithContext, func(ctx context.Context, method, url string, body io.Reader) (*Request, error) {
			actualURL = url
			requestMethod = method
			return nil, nil
		}))

		responseReportString := `{
			"resultsPerPage": 1,
			"startIndex": 0,
			"totalResults": 1,
			"result": {
				"CVE_data_type": "CVE",
				"CVE_data_format": "MITRE",
				"CVE_data_version": "4.0",
				"CVE_data_timestamp": "2022-02-01T17:37Z",
				"CVE_Items": [
					{
						"cve": {
							"data_type": "CVE",
							"data_format": "MITRE",
							"data_version": "4.0",
							"CVE_data_meta": {
								"ID": "CVE-2020-29292",
								"ASSIGNER": "cve@mitre.org"
							},
							"problemtype": {
								"problemtype_data": [
									{ "description": [{ "lang": "en", "value": "CWE-352" }] }
								]
							},
							"references": {
								"reference_data": [
									{
										"url": "https://github.com/Nitya91/iBall-WRD12EN-1.0.0",
										"name": "https://github.com/Nitya91/iBall-WRD12EN-1.0.0",
										"refsource": "MISC",
										"tags": ["Third Party Advisory"]
									},
									{
										"url": "https://www.iball.co.in/",
										"name": "https://www.iball.co.in/",
										"refsource": "MISC",
										"tags": ["Vendor Advisory"]
									}
								]
							},
							"description": {
								"description_data": [
									{
										"lang": "en",
										"value": "iBall WRD12EN 1.0.0 devices allow cross-site request forgery (CSRF) attacks as demonstrated by enabling DNS settings or modifying the range for IP addresses."
									}
								]
							}
						},
						"configurations": {
							"CVE_data_version": "4.0",
							"nodes": [
								{
									"operator": "AND",
									"children": [
										{
											"operator": "OR",
											"children": [],
											"cpe_match": [
												{
													"vulnerable": true,
													"cpe23Uri": "cpe:2.3:o:iball:wrd12en_firmware:1.0.0:*:*:*:*:*:*:*",
													"cpe_name": []
												}
											]
										},
										{
											"operator": "OR",
											"children": [],
											"cpe_match": [
												{
													"vulnerable": false,
													"cpe23Uri": "cpe:2.3:h:iball:wrd12en:-:*:*:*:*:*:*:*",
													"cpe_name": []
												}
											]
										}
									],
									"cpe_match": []
								}
							]
						},
						"impact": {
							"baseMetricV3": {
								"cvssV3": {
									"version": "3.1",
									"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
									"attackVector": "NETWORK",
									"attackComplexity": "LOW",
									"privilegesRequired": "NONE",
									"userInteraction": "REQUIRED",
									"scope": "UNCHANGED",
									"confidentialityImpact": "NONE",
									"integrityImpact": "HIGH",
									"availabilityImpact": "NONE",
									"baseScore": 7.5,
									"baseSeverity": "MEDIUM"
								},
								"exploitabilityScore": 2.8,
								"impactScore": 3.6
							},
							"baseMetricV2": {
								"cvssV2": {
									"version": "2.0",
									"vectorString": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
									"accessVector": "NETWORK",
									"accessComplexity": "MEDIUM",
									"authentication": "NONE",
									"confidentialityImpact": "NONE",
									"integrityImpact": "PARTIAL",
									"availabilityImpact": "NONE",
									"baseScore": 4.3
								},
								"severity": "MEDIUM",
								"exploitabilityScore": 8.6,
								"impactScore": 2.9,
								"acInsufInfo": false,
								"obtainAllPrivilege": false,
								"obtainUserPrivilege": false,
								"obtainOtherPrivilege": false,
								"userInteractionRequired": true
							}
						},
						"publishedDate": "2021-12-30T17:15Z",
						"lastModifiedDate": "2022-01-10T21:11Z"
					}
				]
			}
		}`
		NVDResponseBody := ioutil.NopCloser(bytes.NewBufferString(responseReportString))
		NVDClient := http.DefaultClient
		NVDResp := &Response{
			StatusCode: http.StatusOK,
			Body:       NVDResponseBody,
		}
		patches = append(patches, ApplyMethod(reflect.TypeOf(NVDClient), "Do", func(client *http.Client, req *Request) (*Response, error) {
			return NVDResp, nil
		}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should successfully request CVE from NVD", func() {
			ExpectedNVDReportData := &nvd.NVDReport{}
			json.Unmarshal([]byte(responseReportString), &ExpectedNVDReportData)

			actualReport, _ := nvd.GetNVD(ctx1, "I am cool IOC 3456", NVDClient)
			So(actualReport, ShouldResemble, ExpectedNVDReportData)
		})

		Convey("should set proper URL and request params", func() {
			ioc := "google545684.com"
			u, _ := url.Parse(nvd.NVDEndpoint)
			u.Path = path.Join(u.Path, ioc)
			expectedURL := u.String()
			nvd.GetNVD(ctx1, ioc, NVDClient)
			So(actualURL, ShouldResemble, expectedURL)
			So(requestMethod, ShouldResemble, http.MethodGet)
		})

		Convey("should return error as output result if something goes wrong", func() {
			NVDResp.StatusCode = http.StatusBadGateway
			_, err := nvd.GetNVD(ctx1, "I am cool IOC 3456", NVDClient)
			So(err, ShouldResemble, fmt.Errorf("bad status code: %d", NVDResp.StatusCode))
		})

	})
}
