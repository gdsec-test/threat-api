package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	vtlib "github.com/gdcorp-infosec/threat-api/apis/virustotal/virustotalLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"

	. "github.com/agiledragon/gomonkey/v2"
	. "github.com/smartystreets/goconvey/convey"
)

func TestProcessRequest(t *testing.T) {

	Convey("ProcessRequest", t, func() {
		// setup stubs\mocks
		patches := []*Patches{}

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})
		ctx1 := context.Background()

		// prepare mock input triage request
		triageRequest := triage.Request{
			IOCs:     []string{"574cf0062911c8c4eca2156187b8207F"},
			IOCsType: "MD5",
			JWT:      "Mock JWT token",
			Verbose:  false,
		}
		triageModule := &TriageModule{}

		Convey("Should process triage request", func() {

			virusTotalMetaDataHolder := &vtlib.MetaData{}
			metaDataString := `{Harmless:0, Malicious:0, Suspicious:0, Timeout:0, Undetected:0}`
			json.Unmarshal([]byte(metaDataString), &virusTotalMetaDataHolder)

			date := time.Now()
			expectedTriageData := &triage.Data{
				Title:    "VirusTotal",
				Metadata: []string{"Found 0 matching MD5 hashes", fmt.Sprintf("The last analysis run on %v returned scan result counts of (harmless/malicious/suspicious/timeout/undetected): 0 / 0 / 0 / 0 / 0", date.Format("2006-January-02"))},
				DataType: "",
				Data:     "MD5,SHA1,SHA256,Magic,File Size,First Seen,Reputation,Harmless,Malicious,Suspicious,Timeout,Undetected,Badness\n",
			}

			actualTriageData, _ := triageModule.ProcessRequest(ctx1, &triageRequest, "")

			println(actualTriageData)

			So(actualTriageData, ShouldResemble, expectedTriageData)
		})

	})
}
