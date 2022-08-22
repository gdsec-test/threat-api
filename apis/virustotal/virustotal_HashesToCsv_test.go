package main

import (
	"encoding/json"
	"fmt"
	"regexp"
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

			fakeIocs := []string{
				"hash0",
				"hash1",
			}
			expectedCSV := fmt.Sprintf("IoC,Badness,MD5,SHA1,SHA256,File Size,First Seen,Reputation,Harmless,Malicious,Suspicious,Timeout,Undetected\n%s,0.00,This is a fake response,This is a fake response,This is a fake response,1647895417,2022-03-21T13:43:37-07:00,1647895417,0,0,0,0,0\n%s,0.00,This is a fake response,This is a fake response,This is a fake response,1647895417,2022-03-21T13:43:37-07:00,1647895417,0,0,0,0,0\n", fakeIocs[0], fakeIocs[1])
			removeLocaTimezone := regexp.MustCompile(`\d{4}-\d{2}-\d{2}[^,]*`)
			expectedCSV = removeLocaTimezone.ReplaceAllString(expectedCSV, "$1")
			mockPayloads := make([]VirusTotalObject, 2)
			mockPayloads[0] = &Object{}
			mockPayloads[1] = &Object{}
			actualCSV := HashesToCsv(fakeIocs, mockPayloads, virusTotalMetaDataHolder)
			actualCSV = removeLocaTimezone.ReplaceAllString(actualCSV, "$1")
			So(actualCSV, ShouldResemble, expectedCSV)
		})

	})
}
