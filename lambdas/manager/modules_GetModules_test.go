package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	"github.com/aws/aws-lambda-go/events"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/smartystreets/goconvey/convey"
)

func TestGetModulesAPI(t *testing.T) {

	Convey("GetModules", t, func() {
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()
		APIGatewayRequest := &events.APIGatewayProxyRequest{
			Path: "",
		}
		getModulesListString := `{
			"trustar": {
				"supportedIOCTypes": [
					"DOMAIN",
					"IP",
					"MD5",
					"SHA1",
					"SHA256",
					"URL",
					"CVE",
					"EMAIL"
				]
			},
			"cmap": {
				"supportedIOCTypes": [
					"DOMAIN"
				],
				"actions": {
					"Run": {
						"requiredADGroups": ["ENG-Threat Research", "ENG-DCU"]
					},
					"ViewPII": {
						"requiredADGroups": ["ENG-Threat Research", "ENG-DCU"]
					}
				}
			}
		}`

		var GetModulesList map[string]LambdaMetadata
		json.Unmarshal([]byte(getModulesListString), &GetModulesList)
		patches = append(patches, ApplyMethod(reflect.TypeOf(to), "GetModules",
			func(t *toolbox.Toolbox, ctx context.Context) (map[string]LambdaMetadata, error) {
				return GetModulesList, nil
			}))

		Convey("should return proper list of modules supported", func() {
			marshalledData, _ := json.Marshal(GetModulesList)
			expectedGetModulesResponse := events.APIGatewayProxyResponse{StatusCode: 200, Body: string(marshalledData)}
			actualGetModulesResponse, _ := GetModules(ctx1, *APIGatewayRequest)
			So(actualGetModulesResponse, ShouldResemble, expectedGetModulesResponse)
		})

		Convey("should return error if modules list failed to be returned", func() {
			err := errors.New("I am error during retriaval of modules")
			patches = append(patches, ApplyMethod(reflect.TypeOf(to), "GetModules",
				func(t *toolbox.Toolbox, ctx context.Context) (map[string]LambdaMetadata, error) {
					return nil, err
				}))
			expectedGetModulesResponse := events.APIGatewayProxyResponse{StatusCode: 500}
			actualGetModulesResponse, actualError := GetModules(ctx1, *APIGatewayRequest)
			So(actualGetModulesResponse, ShouldResemble, expectedGetModulesResponse)
			So(actualError, ShouldResemble, fmt.Errorf("error getting modules: %w", err))
		})

		Convey("should return error if cannot unmarshal modules list", func() {
			err := errors.New("I am error during unmarshal of modules")
			patches = append(patches, ApplyFunc(json.Marshal,
				func(v interface{}) ([]byte, error) {
					return nil, err
				}))
			expectedGetModulesResponse := events.APIGatewayProxyResponse{StatusCode: 500, Body: "Error marshalling response"}
			actualGetModulesResponse, actualError := GetModules(ctx1, *APIGatewayRequest)
			So(actualGetModulesResponse, ShouldResemble, expectedGetModulesResponse)
			So(actualError, ShouldResemble, fmt.Errorf("error marshalling response: %w", err))
		})
	})
}
