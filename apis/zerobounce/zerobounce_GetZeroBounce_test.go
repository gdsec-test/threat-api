package main

import (
	"bytes"
	"context"
	"encoding/json"
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
		patches = append(patches, ApplyFunc(http.NewRequestWithContext, func(ctx context.Context, method, url string, body io.Reader) (*Request, error) {
			actualURL = url
			requestMethod = method
			return nil, nil
		}))

		responseReportString := `"email_batch":[
			{
			   "address":"aajgkgkasjdfs@gmail.com",
			   "status":"invalid",
			   "sub_status":"mailbox_not_found",
			   "free_email":true,
			   "did_you_mean":null,
			   "account":"aajgkgkasjdfs",
			   "domain":"gmail.com",
			   "domain_age_days":"9698",
			   "smtp_provider":"google",
			   "mx_found":"true",
			   "mx_record":"gmail-smtp-in.l.google.com",
			   "firstname":null,
			   "lastname":null,
			   "gender":null,
			   "country":null,
			   "region":null,
			   "city":null,
			   "zipcode":null,
			   "processed_at":"2022-03-01 23:37:51.573"
			},
			{
			   "address":"abramsunnycklj8100@gmail.com",
			   "status":"valid",
			   "sub_status":"",
			   "free_email":true,
			   "did_you_mean":null,
			   "account":"abramsunnycklj8100",
			   "domain":"gmail.com",
			   "domain_age_days":"9698",
			   "smtp_provider":"google",
			   "mx_found":"true",
			   "mx_record":"gmail-smtp-in.l.google.com",
			   "firstname":null,
			   "lastname":null,
			   "gender":null,
			   "country":null,
			   "region":null,
			   "city":null,
			   "zipcode":null,
			   "processed_at":"2022-03-01 23:37:51.573"
			},
			{
			   "address":"accountexec321312@caexpressevictions.com",
			   "status":"catch-all",
			   "sub_status":"",
			   "free_email":false,
			   "did_you_mean":null,
			   "account":"accountexec321312",
			   "domain":"caexpressevictions.com",
			   "domain_age_days":"236",
			   "smtp_provider":null,
			   "mx_found":"true",
			   "mx_record":"mail.caexpressevictions.com",
			   "firstname":null,
			   "lastname":null,
			   "gender":null,
			   "country":null,
			   "region":null,
			   "city":null,
			   "zipcode":null,
			   "processed_at":"2022-03-01 23:37:51.573"
			},
			{
			   "address":"adam@circlecityacers.com",
			   "status":"invalid",
			   "sub_status":"does_not_accept_mail",
			   "free_email":false,
			   "did_you_mean":null,
			   "account":"adam",
			   "domain":"circlecityacers.com",
			   "domain_age_days":"3828",
			   "smtp_provider":"",
			   "mx_found":"false",
			   "mx_record":null,
			   "firstname":null,
			   "lastname":null,
			   "gender":null,
			   "country":null,
			   "region":null,
			   "city":null,
			   "zipcode":null,
			   "processed_at":"2022-03-01 23:37:53.619"
			},
			{
			   "address":"adelef0jt@hotmail.com",
			   "status":"valid",
			   "sub_status":"",
			   "free_email":true,
			   "did_you_mean":null,
			   "account":"adelef0jt",
			   "domain":"hotmail.com",
			   "domain_age_days":"9471",
			   "smtp_provider":"microsoft",
			   "mx_found":"true",
			   "mx_record":"hotmail-com.olc.protection.outlook.com",
			   "firstname":null,
			   "lastname":null,
			   "gender":null,
			   "country":null,
			   "region":null,
			   "city":null,
			   "zipcode":null,
			   "processed_at":"2022-03-01 23:37:51.573"
			}
		 ],
		 "errors":[]
		 }`

		errResponseReportString := `{"EmailBatch”:[
				]"struct"{
				   "Address string""json:\"address\"""; Status string""json:\"status\"""; SubStatus string""json:\"sub_status\"""; FreeEmail bool""json:\"free_email\"""; DidYouMean interface"{  
				   }"json:\"did_you_mean\"""; Account string""json:\"account\"""; Domain string""json:\"domain\"""; DomainAgeDays string""json:\"domain_age_days\"""; SMTPProvider string""json:\"smtp_provider\"""; MxFound string""json:\"mx_found\"""; MxRecord string""json:\"mx_record\"""; Firstname string""json:\"firstname\"""; Lastname string""json:\"lastname\"""; Gender string""json:\"gender\"""; Country interface"{
				   }"json:\"country\"""; Region interface"{
				   }"json:\"region\"""; City interface"{
				   }"json:\"city\"""; Zipcode interface"{
				   }"json:\"zipcode\"""; ProcessedAt string""json:\"processed_at\""
				}"(nil)",
				"Errors":[
				]"interface"{	   
				}"(nil)"
			 }`

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

		Convey("should successfully make requests to the zerobounce batch email verification API", func() {
			ExpectedZeroBounceReportData := &zb.ZeroBounceReport{}
			json.Unmarshal([]byte(responseReportString), &ExpectedZeroBounceReportData)

			actualReport, _ := zb.GetZeroBounce(ctx1, "", "", "", zeroBounceClient)
			So(actualReport, ShouldResemble, ExpectedZeroBounceReportData)
		})

		Convey("should set proper URL and request params", func() {
			u, _ := url.Parse(zb.ZerobounceEndpoint)
			u.Path = path.Join(u.Path, "")
			expectedURL := u.String()
			zb.GetZeroBounce(ctx1, "", "", "", zeroBounceClient)
			So(actualURL, ShouldResemble, expectedURL)
			So(requestMethod, ShouldResemble, http.MethodPost)
		})

		Convey("should return error as output result if something goes wrong", func() {
			errReportData := &zb.ZeroBounceReport{}
			json.Unmarshal([]byte(errResponseReportString), &errReportData)

			ExpectedZeroBounceReportData, _ := zb.GetZeroBounce(ctx1, "", "", "", zeroBounceClient)
			So(errReportData, ShouldResemble, ExpectedZeroBounceReportData)
		})

	})
}
