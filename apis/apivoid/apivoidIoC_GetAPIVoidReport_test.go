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
	"reflect"
	"testing"
	. "github.com/agiledragon/gomonkey/v2"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
	. "github.com/smartystreets/goconvey/convey"
)

func TestGetAPIVoidReport(t *testing.T) {

	Convey("GetAPIVoidReport", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()
		APIvoidReportData := &APIvoidReport{}
		patches = append(patches, ApplyFunc(ReformatResponse, func(responseBody io.ReadCloser) (*APIvoidReport, error) {
			return APIvoidReportData, nil
		}))
		actualURL := ""
		requestMethod := ""
		patches = append(patches, ApplyFunc(http.NewRequestWithContext, func(ctx context.Context, method, url string, body io.Reader) (*Request, error) {
			actualURL = url
			requestMethod = method
			return nil, nil
		}))
		APIVoidResponseBody := ioutil.NopCloser(bytes.NewBufferString("API Body response"))
		APIvoidClient := http.DefaultClient
		APIvoidResp := &Response{
			StatusCode: http.StatusOK,
			Body: APIVoidResponseBody,
		}
		patches = append(patches, ApplyMethod(reflect.TypeOf(APIvoidClient), "Do", func(client *http.Client, req *Request) (*Response, error) {
			return APIvoidResp, nil
		}))

		APIVoidKey := "some important key"

		expectedReport := `{
			"fullReportS3URL": "I am super report"
		}`
		json.Unmarshal([]byte(expectedReport), &APIvoidReportData)

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should return proper output result report", func() {
			actualReport, _ := GetAPIVoidReport(ctx1, "I am IOC", APIvoidClient, triage.DomainType, APIVoidKey)
			So(APIvoidReportData.FullReportS3URL, ShouldResemble, actualReport.FullReportS3URL)
		})

		Convey("should set proper URL and request params", func() {
			APIVoidKey = "I_changed_to_anotherKey"
			ioc := "google5634562.com"
			expectedURL := fmt.Sprintf(APIvoidEndpoint, "domainbl", "host", ioc, APIVoidKey)
			GetAPIVoidReport(ctx1, ioc, APIvoidClient, triage.DomainType, APIVoidKey)
			So(actualURL, ShouldResemble, expectedURL)
			So(requestMethod, ShouldResemble, http.MethodGet)
		})

		Convey("should return error as output result if something goes wrong", func() {
			APIvoidResp.StatusCode = http.StatusBadRequest
			_, err := GetAPIVoidReport(ctx1, "I am IOC", APIvoidClient, triage.DomainType, APIVoidKey)
			So(err, ShouldResemble, fmt.Errorf("bad response status code: %d", APIvoidResp.StatusCode))
		})

	})
}
