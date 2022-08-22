package main

import (
	"encoding/json"
	"fmt"
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

			fakeIocs := []string{
				"127.0.0.1",
				"255.255.255.255",
			}
			expectedCSV := fmt.Sprintf("IoC,Badness,Owner,ASN,Country,Harmless,Malicious,Suspicious,Timeout,Undetected\n%s,0.00,This is a fake response,1647895417,This is a fake response,0,0,0,0,0\n%s,0.00,This is a fake response,1647895417,This is a fake response,0,0,0,0,0\n", fakeIocs[0], fakeIocs[1])

			mockPayloads := make([]VirusTotalObject, 2)
			mockPayloads[0] = &Object{}
			mockPayloads[1] = &Object{}
			actualCSV := IpsToCsv(fakeIocs, mockPayloads, virusTotalMetaDataHolder)

			So(actualCSV, ShouldResemble, expectedCSV)
		})

	})
}
