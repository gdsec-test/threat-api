package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"

	sn "github.com/gdcorp-infosec/threat-api/apis/servicenow/servicenowLibrary"
	. "github.com/smartystreets/goconvey/convey"
)

func TestGetRows(t *testing.T) {

	Convey("GetRows", t, func() {
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
		ServiceNowResponseBody := ioutil.NopCloser(bytes.NewBufferString(`{
			"result": []
		}`))
		ServiceNowResp := &http.Response{
			StatusCode: 404,
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

		Convey("should have proper request params for creating ticket", func() {
			rows := make(chan sn.Row)
			query := "some sn qieru 34563456"
			paramValues := url.Values{
				"sysparm_exclude_ref_link": []string{"true"},
			}
			params := url.Values{}
			params.Add("sysparm_limit", fmt.Sprintf("%d", 1000))
			params.Add("sysparm_query", fmt.Sprintf("%s", query))
			for key, values := range paramValues {
				for _, value := range values {
					params.Add(key, value)
				}
			}
			tableURL, _ := url.Parse(fmt.Sprintf("%s/api/now/v1/table/%s", snUrl, snTableName))
			expectedURL := fmt.Sprintf("%s?%s", tableURL, params.Encode())
			expectedMethod := http.MethodGet
			SNClient.GetRows(ctx1, query, paramValues, rows)
			pageCount := regexp.MustCompile(`sysparm_offset=\d+&`)
			So(pageCount.ReplaceAllString(actualURL, ""), ShouldResemble, expectedURL)
			So(requestMethod, ShouldResemble, expectedMethod)
			So(actualContentType, ShouldResemble, "")
			So(actualBody, ShouldResemble, nil)
		})

	})
}
