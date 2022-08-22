package main

import (
	"encoding/json"
	"fmt"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	vtlib "github.com/gdcorp-infosec/threat-api/apis/virustotal/virustotalLibrary"

	. "github.com/smartystreets/goconvey/convey"
)

func TestDomainsToCsv(t *testing.T) {

	Convey("DomainsToCsv", t, func() {
		// setup stubs\mocks
		patches := []*Patches{}

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("Should dump proper CSV output for Domains", func() {

			virusTotalMetaDataHolder := &vtlib.MetaData{}
			metaDataString := `{Harmless:0, Malicious:0, Suspicious:0, Timeout:0, Undetected:0}`
			json.Unmarshal([]byte(metaDataString), &virusTotalMetaDataHolder)

			fakeIocs := []string{
				"goto.nowhere",
				"some.site",
			}
			expectedCSV := fmt.Sprintf("IoC,Badness,Created,Reputation,WHOIS,Harmless,Malicious,Suspicious,Timeout,Undetected\n%s,0.00,1969-12-31T19:01:05-05:00,1647895417,This is a test string,0,0,0,0,0\n%s,0.00,1969-12-31T19:01:05-05:00,65,This is a test string,0,0,0,0,0\n", fakeIocs[0], fakeIocs[1])

			mockPayloads := make([]VirusTotalObject, 2)
			mockPayloads[0] = &Object{}
			mockPayloads[1] = &Object{}

			patches = append(patches, ApplyFunc(DomainsToCsv, func(iocs []string, payloads []VirusTotalObject, metaDataHolder *vtlib.MetaData) string {
				mockPayloads = payloads
				virusTotalMetaDataHolder = metaDataHolder
				return expectedCSV
			}))

			actualCSV := DomainsToCsv(fakeIocs, mockPayloads, virusTotalMetaDataHolder)

			So(actualCSV, ShouldResemble, expectedCSV)
		})

	})
}
