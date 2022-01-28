package main

import (
	"encoding/json"
	"io"
	"strings"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"

	. "github.com/smartystreets/goconvey/convey"
)

func TestReformatResponse(t *testing.T) {

	Convey("ReformatResponse", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		APIvoidReportData := &APIvoidReport{}
		responseJSON := `{"data":{"report":{"blacklists":{"engines":{"0":{"engine":"engine63451"}}}}}}`
		APIVoidResponseBody := io.NopCloser(strings.NewReader(responseJSON))

		expectedReport := `{
			"data":{
				"report": {
					"blacklists": {
						"engines": [
								{ "engine": "engine63451"}
							]
						}
					}
				}
			}`
		json.Unmarshal([]byte(expectedReport), &APIvoidReportData)

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should reformat Engines to a shape of array", func() {
			actualReport, _ := ReformatResponse(APIVoidResponseBody)
			So(APIvoidReportData.Data.Report.Blacklist.Engines, ShouldResemble, actualReport.Data.Report.Blacklist.Engines)
		})

	})
}
