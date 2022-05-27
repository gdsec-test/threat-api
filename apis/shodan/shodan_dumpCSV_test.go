package main

import (
	"encoding/json"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/smartystreets/goconvey/convey"
)

func TestDumpCSV(t *testing.T) {

	Convey("dumpCSV", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should dump proper CSV output ", func() {

			// mock host 1
			ShodanHost1 := Host{}
			responseHostString := `{
				"Domain": "test domain",
    			"ShodanHost": {
				"ip_str":"23.129.64.142",
				"asn":"AS396507",
				"isp":"Emerald Onion",
				"os":"",
				"hostnames": ["hostname1"],
                "org": "mock org1",
				"vulns": [ "some vuln" ],
				"last_update":"2022-03-24T20:17:22.865113",
				"ports":[80,443]
				}
			 }`
			json.Unmarshal([]byte(responseHostString), &ShodanHost1)

			// mock host 2
			ShodanHost2 := Host{}
			responseHostString = `{
				"Domain": "test ip 85.108.57.156",
    			"ShodanHost": {
				"ip_str":"85.108.57.156",
				"asn":"AS901402",
				"isp":"Mock ISP",
				"os":"",
				"hostnames": ["hostname1","hostname2"],
                "org": "mock org2",
				"vulns": [ "mock vuln1", "mock vuln2" ],
				"last_update":"2022-03-24T20:17:22.865113",
				"ports":[80,443,8080,6800,7000]
				}
			 }`
			json.Unmarshal([]byte(responseHostString), &ShodanHost2)

			// create slice of mock hosts
			ShodanHosts := make([]*Host, 2)
			ShodanHosts[0] = &ShodanHost1
			ShodanHosts[1] = &ShodanHost2

			expectedCSV := "Domain,IP,ASN,City,Country,ISP,OS,Hostnames,Vulnerabilities,LastUpdate,Ports\ntest domain,23.129.64.142,AS396507,,,Emerald Onion,,hostname1,some vuln,2022-03-24T20:17:22.865113,80 443\ntest ip 85.108.57.156,85.108.57.156,AS901402,,,Mock ISP,,hostname1 hostname2,mock vuln1 mock vuln2,2022-03-24T20:17:22.865113,80 443 8080 6800 7000\n"

			actualCSV := dumpCSV(ShodanHosts)

			So(actualCSV, ShouldResemble, expectedCSV)
		})

	})
}
