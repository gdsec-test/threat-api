package main

import (
	"encoding/json"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	vtlib "github.com/gdcorp-infosec/threat-api/apis/virustotal/virustotalLibrary"

	. "github.com/smartystreets/goconvey/convey"
)

func TestIpsToCsv(t *testing.T) {

	Convey("IpsToCsv", t, func() {
		// setup stubs\mocks
		patches := []*Patches{}

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("Should dump proper CSV output for IPs", func() {

			virusTotalMetaDataHolder := &vtlib.MetaData{}
			metaDataString := `{Harmless:0, Malicious:0, Suspicious:0, Timeout:0, Undetected:0}`
			json.Unmarshal([]byte(metaDataString), &virusTotalMetaDataHolder)

			expectedCSV := "Owner,ASN,Country,Harmless,Malicious,Suspicious,Timeout,Undetected,Badness\nThis is a fake response,1647895417,This is a fake response,0,0,0,0,0,0.00\nThis is a fake response,1647895417,This is a fake response,0,0,0,0,0,0.00\n"

			fakeIocs := []string{
				"127.0.0.1",
				"255.255.255.255",
			}
			mockPayloads := make([]VirusTotalObject, 2)
			mockPayloads[0] = &Object{}
			mockPayloads[1] = &Object{}
			actualCSV := IpsToCsv(fakeIocs, mockPayloads, virusTotalMetaDataHolder)

			So(actualCSV, ShouldResemble, expectedCSV)
		})

	})
}
