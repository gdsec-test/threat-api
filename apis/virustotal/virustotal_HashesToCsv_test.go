package main

import (
	"encoding/json"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	vtlib "github.com/gdcorp-infosec/threat-api/apis/virustotal/virustotalLibrary"

	. "github.com/smartystreets/goconvey/convey"
)

func TestHashesToCsv(t *testing.T) {

	Convey("HashesToCsv", t, func() {
		// setup stubs\mocks
		patches := []*Patches{}

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("Should dump proper CSV output for Hashes", func() {

			virusTotalMetaDataHolder := &vtlib.MetaData{}
			metaDataString := `{Harmless:0, Malicious:0, Suspicious:0, Timeout:0, Undetected:0}`
			json.Unmarshal([]byte(metaDataString), &virusTotalMetaDataHolder)

			expectedCSV := "MD5,SHA1,SHA256,Magic,File Size,First Seen,Reputation,Harmless,Malicious,Suspicious,Timeout,Undetected,Badness\nThis is a fake response,This is a fake response,This is a fake response,This is a fake response,1647895417,2022-03-21T20:43:37Z,1647895417,0,0,0,0,0,0.00\nThis is a fake response,This is a fake response,This is a fake response,This is a fake response,1647895417,2022-03-21T20:43:37Z,1647895417,0,0,0,0,0,0.00\n"

			mockPayloads := make([]VirusTotalObject, 2)
			mockPayloads[0] = &Object{}
			mockPayloads[1] = &Object{}
			actualCSV := HashesToCsv(mockPayloads, virusTotalMetaDataHolder)

			So(actualCSV, ShouldResemble, expectedCSV)
		})

	})
}
