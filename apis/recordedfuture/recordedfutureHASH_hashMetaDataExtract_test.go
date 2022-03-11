package main

import (
	"encoding/json"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	rf "github.com/gdcorp-infosec/threat-api/apis/recordedfuture/recordedfutureLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/smartystreets/goconvey/convey"
)

func TestHashMetaDataExtract(t *testing.T) {

	Convey("hashMetaDataExtract", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should extrac proper HASH metadata ", func() {
			RecordedFutureHASHReportData := &rf.HashReport{}

			responseReportString := TestRecordedFutureHASHReportData
			json.Unmarshal([]byte(responseReportString), &RecordedFutureHASHReportData)

			expectedMetadata := []string{"1 HASH's have a risk score > 60"}

			reports := map[string]*rf.HashReport{
				"123456": RecordedFutureHASHReportData,
			}
			actualMetadata := hashMetaDataExtract(reports)
			So(actualMetadata, ShouldResemble, expectedMetadata)
		})

	})
}
