package main

import (
	"encoding/json"
	"regexp"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	vtlib "github.com/gdcorp-infosec/threat-api/apis/virustotal/virustotalLibrary"

	. "github.com/smartystreets/goconvey/convey"
)

func TestUrlsToCsv(t *testing.T) {

	Convey("UrlsToCsv", t, func() {
		// setup stubs\mocks
		patches := []*Patches{}

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("Should dump proper CSV output for URLs", func() {

			virusTotalMetaDataHolder := &vtlib.MetaData{}
			metaDataString := `{Harmless:0, Malicious:0, Suspicious:0, Timeout:0, Undetected:0}`
			json.Unmarshal([]byte(metaDataString), &virusTotalMetaDataHolder)

			expectedCSV := "URL,Title,Reputation,First Submission,Harmless,Malicious,Suspicious,Timeout,Undetected,Badness\nThis is a fake response,This is a fake response,1647895417,2022-03-21T13:43:37-07:00,0,0,0,0,0,0.00\nThis is a fake response,This is a fake response,1647895417,2022-03-21T13:43:37-07:00,0,0,0,0,0,0.00\n"
			removeLocaTimezone := regexp.MustCompile(`(\d{4}-\d{2}-\d{2})[^,]*`)
			expectedCSV = removeLocaTimezone.ReplaceAllString(expectedCSV, "$1")
			mockPayloads := make([]VirusTotalObject, 2)
			mockPayloads[0] = &Object{}
			mockPayloads[1] = &Object{}
			actualCSV := UrlsToCsv(mockPayloads, virusTotalMetaDataHolder)
			actualCSV = removeLocaTimezone.ReplaceAllString(actualCSV, "$1")
			So(actualCSV, ShouldResemble, expectedCSV)
		})

	})
}
