package main

import (
	"encoding/json"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	rf "github.com/gdcorp-infosec/threat-api/apis/recordedfuture/recordedfutureLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/smartystreets/goconvey/convey"
)

func TestIpMetaDataExtract(t *testing.T) {

	Convey("ipMetaDataExtract", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should extract IP metadata", func() {
			RecordedFutureIPReportData := &rf.IPReport{}

			responseReportString := TestRecordedFutureIPReportData
			json.Unmarshal([]byte(responseReportString), &RecordedFutureIPReportData)

			expectedMetadata := []string{"2 Risky IP's in same CIDR as 123.45.67.89"}

			reports := map[string]*rf.IPReport{
				"123.45.67.89": RecordedFutureIPReportData,
			}
			actualMetadata := ipMetaDataExtract(reports)
			So(actualMetadata, ShouldResemble, expectedMetadata)
		})

	})
}
