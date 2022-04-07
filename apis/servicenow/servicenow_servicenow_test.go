package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	. "net/http"
	"net/url"
	"reflect"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"

	sn "github.com/gdcorp-infosec/threat-api/apis/servicenow/servicenowLibrary"
	. "github.com/smartystreets/goconvey/convey"
)

func TestHttpRequest(t *testing.T) {

	Convey("httpRequest", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()

		snUrl := "I am URL for Srvice NOW API g25g"
		snUser := "I am User for Srvice NOW API bw45g"
		snPass := "I am Password for Srvice NOW API vw34ng"
		snTableName := "cmdb_ci"
		SNClient, _ := sn.New(snUrl, snUser, snPass, snTableName)
		request := Request{
			Header: Header{},
		}
		actualURL := ""
		requestMethod := ""
		var actualBody io.Reader
		patches = append(patches, ApplyFunc(http.NewRequestWithContext, func(ctx context.Context, method, url string, body io.Reader) (*Request, error) {
			actualURL = url
			requestMethod = method
			actualBody = body
			return &request, nil
		}))
		ServiceNowResponseBody := ioutil.NopCloser(bytes.NewBufferString("some body ve4g1bsdgnsdg"))
		ServiceNowClient := http.DefaultClient
		ServiceNowResp := &Response{
			StatusCode: http.StatusOK,
			Body:       ServiceNowResponseBody,
		}
		patches = append(patches, ApplyMethod(reflect.TypeOf(ServiceNowClient), "Do", func(client *http.Client, req *Request) (*Response, error) {
			return ServiceNowResp, nil
		}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should have proper request params", func() {
			expectedURL := " some SN expected URLsver v34f"
			expectedMethod := "GET"
			expectedContentType := "application/json"
			SNClient.HttpRequest(ctx1, expectedMethod, expectedURL, ServiceNowResponseBody, expectedContentType)
			So(actualURL, ShouldResemble, expectedURL)
			So(requestMethod, ShouldResemble, expectedMethod)
			So(requestMethod, ShouldResemble, expectedMethod)
			So(actualBody, ShouldResemble, ServiceNowResponseBody)
		})

		Convey("should add json content type if method is Post or Put", func() {
			expectedURL := " some SN expected URLsver v34f"
			expectedContentType := "application/json"
			SNClient.HttpRequest(ctx1, http.MethodPost, expectedURL, ServiceNowResponseBody, expectedContentType)
			So(request.Header.Get("Content-Type"), ShouldResemble, expectedContentType)
			expectedContentType = "application/json-new"
			SNClient.HttpRequest(ctx1, http.MethodPut, expectedURL, ServiceNowResponseBody, expectedContentType)
			So(request.Header.Get("Content-Type"), ShouldResemble, expectedContentType)
		})

		Convey("should set basic auth with user and password", func() {
			expectedURL := " some SN expected URLsver v34f"
			expectedContentType := "application/json"
			SNClient.HttpRequest(ctx1, http.MethodPost, expectedURL, ServiceNowResponseBody, expectedContentType)
			auth := snUser + ":" + snPass
			So(request.Header.Get("Authorization"), ShouldResemble, "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
		})

	})
}

func TestHttpRequestAndRead(t *testing.T) {

	Convey("HttpRequestAndRead", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()

		snUrl := "I am URL for Srvice NOW API g54g25g"
		snUser := "I am User for Srvice NOW API bsghw45g"
		snPass := "I am Password for Srvice NOW API vw34ww45tng"
		snTableName := "cmdb_ci"
		SNClient, _ := sn.New(snUrl, snUser, snPass, snTableName)
		actualURL := ""
		requestMethod := ""
		var actualBody io.Reader
		ServiceNowResponseBody := ioutil.NopCloser(bytes.NewBufferString("some body ve4g1bsdgnsdg"))
		ServiceNowResp := &Response{
			StatusCode: http.StatusOK,
			Body:       ServiceNowResponseBody,
		}
		patches = append(patches, ApplyMethod(reflect.TypeOf(SNClient), "HttpRequest", func(c *sn.Client, ctx context.Context, method, url string, body io.Reader, contentType string) (*http.Response, error) {
			actualURL = url
			requestMethod = method
			actualBody = body
			return ServiceNowResp, nil
		}))
		var isCalled bool
		patches = append(patches, ApplyFunc(ioutil.ReadAll, func(r io.Reader) ([]byte, error) {
			isCalled = true
			return []byte{}, nil
		}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should have proper request params", func() {
			expectedURL := " some SN expected URLsver v34f"
			expectedMethod := "GET"
			expectedContentType := "application/json"
			SNClient.HttpRequestAndRead(ctx1, expectedMethod, expectedURL, ServiceNowResponseBody, expectedContentType)
			So(actualURL, ShouldResemble, expectedURL)
			So(requestMethod, ShouldResemble, expectedMethod)
			So(requestMethod, ShouldResemble, expectedMethod)
			So(actualBody, ShouldResemble, ServiceNowResponseBody)
			So(isCalled, ShouldResemble, true)
		})

	})
}

func TestUploadFile(t *testing.T) {

	Convey("UploadFile", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()

		snUrl := "I am URL for Srvice NOW API g54g25g"
		snUser := "I am User for Srvice NOW API bsghw45g"
		snPass := "I am Password for Srvice NOW API vw34ww45tng"
		snTableName := "cmdb_ci"
		SNClient, _ := sn.New(snUrl, snUser, snPass, snTableName)
		actualURL := ""
		requestMethod := ""
		actualContentType := ""
		var actualBody io.Reader
		ServiceNowResponseBody := ioutil.NopCloser(bytes.NewBufferString("some body ve4g1bsdgnsdg"))
		ServiceNowResp := &Response{
			StatusCode: http.StatusOK,
			Body:       ServiceNowResponseBody,
		}
		patches = append(patches, ApplyMethod(reflect.TypeOf(SNClient), "HttpRequest", func(c *sn.Client, ctx context.Context, method, url string, body io.Reader, contentType string) (*http.Response, error) {
			actualURL = url
			requestMethod = method
			actualBody = body
			actualContentType = contentType
			return ServiceNowResp, nil
		}))


		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should have proper request params", func() {
			expectedFileData := []byte(" some SN expected URLsver v34f")
			expectedFile := "some file vw34g"
			expectedSysID := "vae4g3vsrv"
			paramValues := url.Values{
				"file_name":    []string{expectedFile},
				"table_name":   []string{snTableName},
				"table_sys_id": []string{expectedSysID},
			}
			parsedUrl, _ := url.Parse(snUrl + "/api/now/v1/attachment/file")
			uploadURL := fmt.Sprintf("%s?%s", parsedUrl, paramValues.Encode())
			SNClient.UploadFile(ctx1, expectedFile, expectedFileData, expectedSysID)
			So(actualURL, ShouldResemble, uploadURL)
			So(requestMethod, ShouldResemble, http.MethodPost)
			So(actualBody, ShouldResemble, bytes.NewReader(expectedFileData))
			So(actualContentType, ShouldResemble, "application/octet-stream")
		})

	})
}
