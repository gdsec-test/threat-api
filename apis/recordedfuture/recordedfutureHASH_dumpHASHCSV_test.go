package main

import (
	"encoding/json"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	rf "github.com/gdcorp-infosec/threat-api/apis/recordedfuture/recordedfutureLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/smartystreets/goconvey/convey"
)

func TestDumpHASHCSV(t *testing.T) {

	Convey("dumpHASHCSV", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should dump proper HASH CSV output ", func() {
			RecorderFutureHASHReportData := &rf.HashReport{}

			responseReportString := TestRecorderFutureHASHReportData
			json.Unmarshal([]byte(responseReportString), &RecorderFutureHASHReportData)

			expectedCSV := "IntelCardLink,Risk Score,Criticality,CriticalityLabel,First Seen,Last Seen,HashAlgorithm,ThreatLists,FileHashes\nhttps://app.recordedfuture.com/live/sc/entity/hash%12345,70,3,Malicious,2019-04-28 06:42:19.004 +0000 UTC,2022-01-25 07:00:04.129 +0000 UTC,MD5,,12345/123456789\n"

			reports := map[string]*rf.HashReport{
				"123456": RecorderFutureHASHReportData,
			}
			actualCSV := dumpHASHCSV(reports)
			So(actualCSV, ShouldResemble, expectedCSV)
		})

	})
}
