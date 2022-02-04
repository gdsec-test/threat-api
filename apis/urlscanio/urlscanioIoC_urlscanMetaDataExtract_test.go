package main

import (
	"encoding/json"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	us "github.com/gdcorp-infosec/threat-api/apis/urlscanio/urlscanioLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/smartystreets/goconvey/convey"
)

func TestUrlscanMetaDataExtract(t *testing.T) {

	Convey("urlscanMetaDataExtract", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should extract proper metadata", func() {
			URLScanIOReportData := &us.ResultHolder{}
			responseReportString := TestURLScanIOResultData
			json.Unmarshal([]byte(responseReportString), &URLScanIOReportData)

			reports := map[string]*us.ResultHolder{
				"https://google.com": URLScanIOReportData,
			}
			expectedMetadata := []string{"\nurlscan.io Submission API used is rate-limited to 5000 public scans per day, 500 per hour and 60 per minute. Result API is rate-limited to 120 requests per minute, 5000 per hour and 10000 per day."}
			metaDataHolder := &us.MetaData{}
			dumpCSV(reports, metaDataHolder)
			actualMetadata := urlscanMetaDataExtract(metaDataHolder)
			So(actualMetadata, ShouldResemble, expectedMetadata)
		})


	})
}
