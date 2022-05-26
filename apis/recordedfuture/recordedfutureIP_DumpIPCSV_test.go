package main

import (
	"encoding/json"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	rf "github.com/gdcorp-infosec/threat-api/apis/recordedfuture/recordedfutureLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/smartystreets/goconvey/convey"
)

func TestDumpIPCSV(t *testing.T) {

	Convey("dumpIPCSV", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should dump proper IP CSV output ", func() {
			RecordedFutureIPReportData := &rf.IPReport{}

			responseReportString := TestRecordedFutureIPReportData
			json.Unmarshal([]byte(responseReportString), &RecordedFutureIPReportData)

			expectedCSV := "IntelCardLink,Risk Score,Criticality,CriticalityLabel,First Seen,Last Seen,ThreatLists,Badness\nhttps://app.recordedfuture.com/live/sc/entity/ip%3A216.151.180.100,15,1,Unusual,2017-04-13 07:54:49.283 +0000 UTC,2017-06-13 01:10:15.003 +0000 UTC,,0.15\n"

			reports := map[string]*rf.IPReport{
				"123.45.67.89": RecordedFutureIPReportData,
			}
			actualCSV := dumpIPCSV(reports)
			So(actualCSV, ShouldResemble, expectedCSV)
		})

	})
}
