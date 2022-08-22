package main

import (
	"encoding/json"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	rf "github.com/gdcorp-infosec/threat-api/apis/recordedfuture/recordedfutureLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/smartystreets/goconvey/convey"
)

func TestDumpCVECSV(t *testing.T) {

	Convey("dumpCVECSV", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should dump proper CVE CSV output ", func() {
			RecordedFutureCVEReportData := &rf.CVEReport{}

			responseReportString := TestRecordedFutureCVEReportData

			json.Unmarshal([]byte(responseReportString), &RecordedFutureCVEReportData)

			expectedCSV := "IoC,Badness,IntelCardLink,Risk Score,Criticality,CriticalityLabel,CommonNames,First Seen,Last Seen,ThreatLists,Affected Machines: CPE,RawRisk Rules Associated,Access Vector,Auth Required,Access Complexity,Confidentiality,Integrity,NVD Description\nCVE-2014-0160,0.89,https://app.recordedfuture.com/live/sc/entity/K5GW38,89,4,Critical,Heartbleed,2013-11-05 15:11:54.893 +0000 UTC,2022-02-03 00:16:48.398 +0000 UTC,,cpe:2.3:a:openssl:openssl:1.0.1d:*:*:*:*:*:*:* cpe:2.3:a:openssl:openssl:1.0.1:beta2:*:*:*:*:*:*,linkedToRAT,NETWORK,NONE,LOW,PARTIAL,NONE,The (1) TLS and (2) DTLS implementations \n"

			reports := map[string]*rf.CVEReport{
				"CVE-2014-0160": RecordedFutureCVEReportData,
			}
			actualCSV := dumpCVECSV(reports)
			So(actualCSV, ShouldResemble, expectedCSV)
		})

	})
}
