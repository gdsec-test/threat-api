package main

import (
	"encoding/json"
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

			expectedCSV := "Created,Reputation,WHOIS,Harmless,Malicious,Suspicious,Timeout,Undetected,Badness\n1969-12-31T19:01:05-05:00,1647895417,This is a test string,0,0,0,0,0,0.00\n1969-12-31T19:01:05-05:00,65,This is a test string,0,0,0,0,0,0.00\n"

			fakeIocs := []string{
				"CVE-1776-001",
				"CVE-1984-007",
			}
			mockPayloads := make([]VirusTotalObject, 2)
			mockPayloads[0] = &Object{}
			mockPayloads[1] = &Object{}

			patches = append(patches, ApplyFunc(DomainsToCsv, func(payloads []VirusTotalObject, metaDataHolder *vtlib.MetaData) string {
				mockPayloads = payloads
				virusTotalMetaDataHolder = metaDataHolder
				return expectedCSV
			}))

			actualCSV := DomainsToCsv(fakeIocs, mockPayloads, virusTotalMetaDataHolder)

			So(actualCSV, ShouldResemble, expectedCSV)
		})

	})
}
