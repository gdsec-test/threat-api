package main

import (
	"encoding/json"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	us "github.com/gdcorp-infosec/threat-api/apis/urlscanio/urlscanioLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/smartystreets/goconvey/convey"
)

func TestDumpCSV(t *testing.T) {

	Convey("dumpCSV", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should dump proper CSV output", func() {
			URLScanIOReportData := &us.ResultHolder{}

			responseReportString := TestURLScanIOResultData

			json.Unmarshal([]byte(responseReportString), &URLScanIOReportData)

			expectedCSV := "Final Redirect URL,Screenshot URL,Overall Verdict Malicious,Overall Verdict Score,Overall Verdicts,Urlscan Verdict Score,Urlscan Verdict Malicious,Engines Verdict Score,Engines Verdict Malicious Total,Engines Verdict Benign Total,Engines Verdict Engines Total,Community Verdict Score,Community Votes Malicious,Community Votes Benign,Community Votes Total,Report URL\nhttps://www.google.com/?gws_rd=ssl,https://urlscan.io/screenshots/66d2bd70-3bfa-407c-a8fe-111111.png,false,0,0,0,false,0,0,0,0,0,0,0,0,https://urlscan.io/result/66d2bd70-3bfa-407c-a8fe-111111/\n"

			reports := map[string]*us.ResultHolder{
				"https://google.com": URLScanIOReportData,
			}
			metaDataHolder := &us.MetaData{}
			actualCSV := dumpCSV(reports, metaDataHolder)
			So(actualCSV, ShouldResemble, expectedCSV)
		})

	})
}
