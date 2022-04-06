package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"

	sn "github.com/gdcorp-infosec/threat-api/apis/servicenow/servicenowLibrary"
	. "github.com/smartystreets/goconvey/convey"
)

func TestCreateTicket(t *testing.T) {

	Convey("CreateTicket", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()

		snUrl := "I am URL for Srvice NOW API g25g"
		snUser := "I am User for Srvice NOW API bw45g"
		snPass := "I am Password for Srvice NOW API vw34ng"
		snTableName := "cmdb_ci"
		SNClient, _ := sn.New(snUrl, snUser, snPass, snTableName)
		actualURL := ""
		requestMethod := ""
		actualContentType := ""
		expectedBody := sn.Body{
			State:   "New",
			Title:   "ThreatAPI client test",
			Summary: "ThreatAPI client to create incident on ServiceNow"}
		fileMap := make(map[string][]byte)
		fileMap["testingfiles"] = []byte(`ok`)

		patches = append(patches, ApplyMethod(reflect.TypeOf(SNClient), "HttpRequestAndRead", func(client *sn.Client, ctx context.Context, method, url string, body io.Reader, contentType string) ([]byte, error) {
			actualURL = url
			requestMethod = method
			actualContentType = contentType
			return []byte(`{
				"result": {
					"sys_id": "some 1923",
					"u_number": "number t234"
				}
			}`), nil
		}))

		actualFilename := ""
		var actualFileData []byte
		actualSysId := ""
		patches = append(patches, ApplyMethod(reflect.TypeOf(SNClient), "UploadFile", func(client *sn.Client, ctx context.Context, fileName string, byteFileData []byte, sysID string) error {
			actualFilename = fileName
			actualSysId = sysID
			actualFileData = byteFileData
			return nil
		}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should have proper request params for creating ticket", func() {
			expectedMethod := "POST"
			expectedURL, _ := url.Parse(fmt.Sprintf("%s/api/now/v1/table/%s", snUrl, snTableName))
			expected := expectedURL.String()
			SNClient.CreateTicket(ctx1, &expectedBody, fileMap, false)
			So(actualURL, ShouldResemble, expected)
			So(requestMethod, ShouldResemble, expectedMethod)
			So(actualContentType, ShouldResemble, "application/json")
		})

		Convey("should have proper request params for file upload", func() {
			ticket, _ := SNClient.CreateTicket(ctx1, &expectedBody, fileMap, false)
			So(actualFilename, ShouldResemble, "testingfiles")
			So(actualSysId, ShouldResemble, "some 1923")
			So(ticket.SysID, ShouldResemble, "some 1923")
			So(ticket.Number, ShouldResemble, "number t234")
			So(actualFileData, ShouldResemble, []byte(`ok`))
		})

	})
}

func TestAppendToSnowTicketWorklogWithSysId(t *testing.T) {

	Convey("AppendToSnowTicketWorklogWithSysId", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()

		snUrl := "I am URL for Srvice NOW API g25g"
		snUser := "I am User for Srvice NOW API bw45g"
		snPass := "I am Password for Srvice NOW API vw34ng"
		snTableName := "cmdb_ci"
		SNClient, _ := sn.New(snUrl, snUser, snPass, snTableName)
		actualURL := ""
		requestMethod := ""
		actualContentType := ""
		sysId := "some sys id vw345g"
		worklogText := "some worklogTextbw45 "
		ServiceNowResponseBody := ioutil.NopCloser(bytes.NewBufferString("some body ve4g1bsdgnsdg"))
		ServiceNowResp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       ServiceNowResponseBody,
		}
		var actualBody io.Reader
		patches = append(patches, ApplyMethod(reflect.TypeOf(SNClient), "HttpRequest", func(client *sn.Client, ctx context.Context, method, url string, body io.Reader, contentType string) (*http.Response, error) {
			actualURL = url
			requestMethod = method
			actualContentType = contentType
			actualBody = body
			return ServiceNowResp, nil
		}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should have proper request params for appeding worklog", func() {
			expectedMethod := "PUT"
			editTicketURLString, _ := url.Parse(fmt.Sprintf("%s/api/now/v1/table/%s", snUrl, snTableName) + "/" + url.QueryEscape(sysId))
			paramValues := url.Values{
				"sysparm_exclude_ref_link": []string{"true"},
			}
			jsonBytes, _ := json.Marshal(map[string]string{"u_narrative": worklogText})
			expected := fmt.Sprintf("%s?%s", editTicketURLString.String(), paramValues.Encode())
			SNClient.AppendToSnowTicketWorklogWithSysId(ctx1, sysId, worklogText)
			So(actualURL, ShouldResemble, expected)
			So(requestMethod, ShouldResemble, expectedMethod)
			So(actualBody, ShouldResemble, bytes.NewReader(jsonBytes))
			So(actualContentType, ShouldResemble, "application/json")
		})

	})
}

func TestCloseSnowTicketWithSysId(t *testing.T) {

	Convey("CloseSnowTicketWithSysId", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()

		snUrl := "I am URL for Srvice NOW API g25g"
		snUser := "I am User for Srvice NOW API bw45g"
		snPass := "I am Password for Srvice NOW API vw34ng"
		snTableName := "cmdb_ci"
		SNClient, _ := sn.New(snUrl, snUser, snPass, snTableName)
		actualURL := ""
		requestMethod := ""
		actualContentType := ""
		var actualBody io.Reader
		sysId := "some sys id vw345gvbq34dsfvq34"
		ServiceNowResponseBody := ioutil.NopCloser(bytes.NewBufferString("some body ve4g1bsdgnsdg"))
		ServiceNowResp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       ServiceNowResponseBody,
		}
		patches = append(patches, ApplyMethod(reflect.TypeOf(SNClient), "HttpRequest", func(client *sn.Client, ctx context.Context, method, url string, body io.Reader, contentType string) (*http.Response, error) {
			actualURL = url
			requestMethod = method
			actualContentType = contentType
			actualBody = body
			return ServiceNowResp, nil
		}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should have proper request params for closing ticket", func() {
			expectedMethod := "PUT"
			editTicketURLString, _ := url.Parse(fmt.Sprintf("%s/api/now/v1/table/%s", snUrl, snTableName) + "/" + url.QueryEscape(sysId))
			paramValues := url.Values{
				"sysparm_exclude_ref_link": []string{"true"},
			}
			jsonBytes, _ := json.Marshal(map[string]string{"u_state": "Closed"})
			expected := fmt.Sprintf("%s?%s", editTicketURLString.String(), paramValues.Encode())
			SNClient.CloseSnowTicketWithSysId(ctx1, sysId)
			So(actualURL, ShouldResemble, expected)
			So(requestMethod, ShouldResemble, expectedMethod)
			So(actualBody, ShouldResemble, bytes.NewReader(jsonBytes))
			So(actualContentType, ShouldResemble, "application/json")
		})

	})
}
