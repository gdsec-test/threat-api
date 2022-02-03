package main

import (
	"encoding/json"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	rf "github.com/gdcorp-infosec/threat-api/apis/recordedfuture/recordedfutureLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/smartystreets/goconvey/convey"
)

func TestCveMetaDataExtract(t *testing.T) {

	Convey("cveMetaDataExtract", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should extrac proper CVE metadata output ", func() {
			RecorderFutureCVEReportData := &rf.CVEReport{}
			responseReportString := TestRecorderFutureCVEReportData

			json.Unmarshal([]byte(responseReportString), &RecorderFutureCVEReportData)

			expectedMetadata := []string{"1 CVE's have a risk score > 60", "CPE's associated with list of CVE's : 2", "Access Vectors for CVE's : NETWORK"}

			reports := map[string]*rf.CVEReport{
				"CVE-2014-0160": RecorderFutureCVEReportData,
			}
			actualMetadata := cveMetaDataExtract(reports)
			So(actualMetadata, ShouldResemble, expectedMetadata)
		})

	})
}
