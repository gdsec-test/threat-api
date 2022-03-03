package main

import (
	"encoding/json"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	zb "github.com/gdcorp-infosec/threat-api/apis/zerobounce/zerobounceLibrary"

	. "github.com/smartystreets/goconvey/convey"
)

func TestCveMetaDataExtract(t *testing.T) {

	Convey("zerobounceMetaDataExtract", t, func() {
		// setup stubs\mocks
		patches := []*Patches{}

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should prepare metadata for input emails", func() {
			zeroBounceReportData := &zb.ZeroBounceReport{}

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
			json.Unmarshal([]byte(responseReportString), &zeroBounceReportData)

			ZeroBounceMetaData := &zb.MetaData{}
			responseMetaDataString := `Valid account(s): 2, Invalid account(s): 2, Catch-all account(s): 1, Spamtrap account(s): 0, Abuse account(s): 0, Do_not_mail account(s): 0, Unkown account(s): 0\n1 Zerobounce API is rate-limited to allow 5 requests per minute with a maximum of 100 emails per request. In case no data is found, the rate limit has been exceeded. Try again in 10 minutes.`
			json.Unmarshal([]byte(responseMetaDataString), &ZeroBounceMetaData)

			expectedMetadata := []string{"Valid account(s): 0, Invalid account(s): 0, Catch-all account(s): 0, Spamtrap account(s): 0, Abuse account(s): 0, Do_not_mail account(s): 0, Unkown account(s): 0", "\nZerobounce API is rate-limited to allow 5 requests per minute with a maximum of 100 emails per request. In case no data is found, the rate limit has been exceeded. Try again in 10 minutes."}

			emails := map[string]*zb.ZeroBounceReport{
				"aajgkgkasjdfs@gmail.com,abramsunnycklj8100@gmail.com,accountexec321312@caexpressevictions.com,adam@circlecityacers.com,adelef0jt@hotmail.com": zeroBounceReportData,
			}
			actualMetadata := zerobounceMetaDataExtract(emails, ZeroBounceMetaData)
			So(actualMetadata, ShouldResemble, expectedMetadata)
		})

	})
}
