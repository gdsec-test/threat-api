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
	"reflect"
	"testing"
	"time"

	. "github.com/agiledragon/gomonkey/v2"
	us "github.com/gdcorp-infosec/threat-api/apis/urlscanio/urlscanioLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/smartystreets/goconvey/convey"
)

func TestGetURLScanResults(t *testing.T) {

	Convey("GetURLScanResults", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()
		responseReportString := TestURLScanIOResultData
		patches = append(patches, ApplyFunc(time.Sleep, func(d time.Duration) {
			return
		}))
		URLScanIOReportData := &us.ResultHolder{}
		json.Unmarshal([]byte(responseReportString), &URLScanIOReportData)
		URSCanIOKey := "super_secret_scn_io_key_4356"

		actualSubmissionURL := ""
		submissiobRequestMethod := ""
		actualResultURL := ""
		resultRequestMethod := ""
		submitionRequest := &Request{
			Header: Header{},
			URL:    &url.URL{},
		}
		resultRequest := &Request{
			Header: Header{},
			URL:    &url.URL{},
		}
		resultURL := "https://urlscan.io/api/v1/result/66d2bd70-3bfa-407c-a8fe-7d5d211bd992/"
		ioc := "https://google.com"
		patches = append(patches, ApplyFunc(http.NewRequestWithContext, func(ctx context.Context, method, urlString string, body io.Reader) (*Request, error) {
			if urlString == resultURL {
				actualResultURL = urlString
				resultRequestMethod = method
				resultRequest.URL, _ = url.Parse(urlString)
				return resultRequest, nil
			} else if urlString == "https://urlscan.io/api/v1/scan/" {
				actualSubmissionURL = urlString
				submissiobRequestMethod = method
				submitionRequest.URL, _ = url.Parse(urlString)
				return submitionRequest, nil
			}
			return &Request{
				Header: Header{},
				URL:    &url.URL{},
			}, nil
		}))

		startJobResponseString := `{
			"message": "Submission successful",
			"uuid": "66d2bd70-3bfa-407c-a8fe-7d5d211bd992",
			"result": "https://urlscan.io/result/66d2bd70-3bfa-407c-a8fe-7d5d211bd992/",
			"api": "` + resultURL + `",
			"visibility": "public",
			"options": {},
			"url": "http://google.com"
		}`
		URLScanIOClient := http.DefaultClient

		URLScanIOSubmitionBody := ioutil.NopCloser(bytes.NewBufferString(startJobResponseString))
		URLScanIOSubmitionResp := &Response{
			StatusCode: http.StatusOK,
			Body:       URLScanIOSubmitionBody,
		}
		URLScanIOResultBody := ioutil.NopCloser(bytes.NewBufferString(responseReportString))
		URLScanIOResp := &Response{
			StatusCode: http.StatusOK,
			Body:       URLScanIOResultBody,
		}
		URLScanRequestsCount := 0
		patches = append(patches, ApplyMethod(reflect.TypeOf(URLScanIOClient), "Do", func(client *http.Client, req *Request) (*Response, error) {
			urlString := req.URL.String()
			if urlString == resultURL {
				URLScanRequestsCount = URLScanRequestsCount + 1
				if URLScanRequestsCount > 1 {
					URLScanIOResp.StatusCode = http.StatusOK
				}
				return URLScanIOResp, nil
			} else if urlString == "https://urlscan.io/api/v1/scan/" {
				return URLScanIOSubmitionResp, nil
			}
			return &Response{
				StatusCode: http.StatusOK,
				Body:       ioutil.NopCloser(bytes.NewBufferString("")),
			}, nil
		}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("Start Report Request", func() {

			Convey("should successfully request sumbition of result from URLScanIO by setting proper params", func() {
				ExpectedURLScanIOReportData := &us.SubmissionResultHolder{}
				json.Unmarshal([]byte(responseReportString), &ExpectedURLScanIOReportData)

				us.GetURLScanResults(ctx1, ioc, URSCanIOKey, URLScanIOClient)
				expectedURL := "https://urlscan.io/api/v1/scan/"
				So(actualSubmissionURL, ShouldResemble, expectedURL)
				So(submissiobRequestMethod, ShouldResemble, http.MethodPost)
				So(submitionRequest.Header.Get("API-Key"), ShouldResemble, URSCanIOKey)
				So(submitionRequest.Header.Get("Content-Type"), ShouldResemble, "application/json")
			})

			Convey("should return error if scan was prevented", func() {
				URLScanIOSubmitionResp.StatusCode = http.StatusBadRequest
				URLScanIOSubmitionResp.Body = ioutil.NopCloser(bytes.NewBufferString("Scan prevented"))
				_, err := us.GetURLScanResults(ctx1, ioc, URSCanIOKey, URLScanIOClient)
				So(err, ShouldResemble, fmt.Errorf("scan prevented"))
			})

			Convey("should return error for DNS Error", func() {
				URLScanIOSubmitionResp.StatusCode = http.StatusBadRequest
				URLScanIOSubmitionResp.Body = ioutil.NopCloser(bytes.NewBufferString("DNS Error"))
				_, err := us.GetURLScanResults(ctx1, ioc, URSCanIOKey, URLScanIOClient)
				So(err, ShouldResemble, fmt.Errorf("dns error"))
			})

			Convey("should return generic error for any bad request", func() {
				URLScanIOSubmitionResp.StatusCode = http.StatusBadGateway
				URLScanIOSubmitionResp.Body = ioutil.NopCloser(bytes.NewBufferString("DNS Error"))
				_, err := us.GetURLScanResults(ctx1, ioc, URSCanIOKey, URLScanIOClient)
				So(err, ShouldResemble, fmt.Errorf("bad status code: %d", URLScanIOSubmitionResp.StatusCode))
			})

		})

		Convey("Report Results Request", func() {

			Convey("should successfully request from URLScanIO  by setting proper params", func() {
				ExpectedURLScanIOReportData := &us.SubmissionResultHolder{}
				json.Unmarshal([]byte(responseReportString), &ExpectedURLScanIOReportData)

				us.GetURLScanResults(ctx1, ioc, URSCanIOKey, URLScanIOClient)
				expectedURL := resultURL
				So(actualResultURL, ShouldResemble, expectedURL)
				So(resultRequestMethod, ShouldResemble, http.MethodGet)
			})

			Convey("should try to repeat request if it is not yet ready", func() {
				URLScanIOResp.StatusCode = http.StatusNotFound
				us.GetURLScanResults(ctx1, ioc, URSCanIOKey, URLScanIOClient)
				So(URLScanRequestsCount, ShouldResemble, 2)
			})

		})

	})
}
