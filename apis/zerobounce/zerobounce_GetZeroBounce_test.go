package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	. "net/http"
	"net/url"
	"path"
	"reflect"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	zb "github.com/gdcorp-infosec/threat-api/apis/zerobounce/zerobounceLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/smartystreets/goconvey/convey"
)

func TestGetZeroBounce(t *testing.T) {

	Convey("GetZeroBounce", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()
		actualURL := ""
		requestMethod := ""
		ZeroBounceRequest := &Request{
			Header: http.Header{},
		}
		patches = append(patches, ApplyFunc(http.NewRequestWithContext, func(ctx context.Context, method, url string, body io.Reader) (*Request, error) {
			actualURL = url
			requestMethod = method
			return ZeroBounceRequest, nil
		}))

		responseReportString := `{
			"email_batch":[
			{
			   "address":"aajgkgkasjdfs@gmail.com",
			   "status":"invalid",
			   "sub_status":"mailbox_not_found",
			   "free_email":true,
			   "account":"aajgkgkasjdfs",
			   "domain":"gmail.com",
			   "domain_age_days":"9698",
			   "smtp_provider":"google",
			   "mx_found":"true",
			   "mx_record":"gmail-smtp-in.l.google.com",
			   "processed_at":"2022-03-01 23:37:51.573"
			}
		 ],
		 "errors":[]
		 }`

		// errResponseReportString := `{"EmailBatch”:[
		// 		]"struct"{
		// 		   "Address string""json:\"address\"""; Status string""json:\"status\"""; SubStatus string""json:\"sub_status\"""; FreeEmail bool""json:\"free_email\"""; DidYouMean interface"{
		// 		   }"json:\"did_you_mean\"""; Account string""json:\"account\"""; Domain string""json:\"domain\"""; DomainAgeDays string""json:\"domain_age_days\"""; SMTPProvider string""json:\"smtp_provider\"""; MxFound string""json:\"mx_found\"""; MxRecord string""json:\"mx_record\"""; Firstname string""json:\"firstname\"""; Lastname string""json:\"lastname\"""; Gender string""json:\"gender\"""; Country interface"{
		// 		   }"json:\"country\"""; Region interface"{
		// 		   }"json:\"region\"""; City interface"{
		// 		   }"json:\"city\"""; Zipcode interface"{
		// 		   }"json:\"zipcode\"""; ProcessedAt string""json:\"processed_at\""
		// 		}"(nil)",
		// 		"Errors":[
		// 		]"interface"{
		// 		}"(nil)"
		// 	 }`

		zeroBounceResponseBody := ioutil.NopCloser(bytes.NewBufferString(responseReportString))
		zeroBounceClient := http.DefaultClient
		zeroBounceResp := &Response{
			StatusCode: http.StatusOK,
			Body:       zeroBounceResponseBody,
		}
		patches = append(patches, ApplyMethod(reflect.TypeOf(zeroBounceClient), "Do", func(client *http.Client, req *Request) (*Response, error) {
			return zeroBounceResp, nil
		}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		// Convey("should successfully make requests to the zerobounce batch email verification API", func() {
		// 	ExpectedZeroBounceReportData := &zb.ZeroBounceReport{}
		// 	json.Unmarshal([]byte(responseReportString), &ExpectedZeroBounceReportData)
		// 	actualReport, _ := zb.GetZeroBounce(ctx1, "", "", "", zeroBounceClient)
		// 	So(actualReport, ShouldResemble, ExpectedZeroBounceReportData)
		// })

		Convey("should set proper URL and request params", func() {
			u, _ := url.Parse(zb.ZerobounceEndpoint)
			u.Path = path.Join(u.Path, "")
			expectedURL := u.String()
			zb.GetZeroBounce(ctx1, "", "", "", zeroBounceClient)
			So(actualURL, ShouldResemble, expectedURL)
			So(requestMethod, ShouldResemble, http.MethodPost)
		})

		Convey("should return error as output result if something goes wrong", func() {
			expectedError := errors.New("I am error during zero bounce request")
			patches = append(patches, ApplyMethod(reflect.TypeOf(zeroBounceClient), "Do", func(client *http.Client, req *Request) (*Response, error) {
				return nil, expectedError
			}))
			_, actualError := zb.GetZeroBounce(ctx1, "", "", "", zeroBounceClient)
			So(actualError, ShouldResemble, expectedError)
		})

	})
}
