package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"reflect"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/ns3777k/go-shodan/v4/shodan"
	. "github.com/smartystreets/goconvey/convey"
)

func TestGetServicesForIPsTest(t *testing.T) {
	Convey("GetServicesForIPs", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()
		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("Should fetch host information for input domains", func() {
			ShodanHost := Host{}
			responseHostString := `{
                "Domain": "Mock IP",
                "ShodanHost": {
                "ip_str":"23.129.64.142",
                "asn":"AS396507",
                "isp":"Emerald Onion",
                "os":"",
                "hostnames": ["hostname1", "hostname2"],
                "org": "Mock org",
                "vulns": [ "Vuln1", "Vuln2" ],
                "last_update":"2022-03-24T20:17:22.865113",
                "ports":[80,443,8080]
                }
             }`
			json.Unmarshal([]byte(responseHostString), &ShodanHost)

			expectedShodanHosts := make([]*Host, 1)
			expectedShodanHosts[0] = &ShodanHost

			// Mock Shodan client
			patches = append(patches, ApplyFunc(shodan.NewClient, func(client *http.Client, token string) *shodan.Client {
				return &shodan.Client{
					Token:          token,
					BaseURL:        "Mock base",
					ExploitBaseURL: "Mock exploit",
					StreamBaseURL:  "Mock stream base",
					Client:         client,
				}
			}))

			// Mock input triage module struct
			shodanKey := "Mock shodan key"
			shodanClient := shodan.NewClient(nil, shodanKey)
			m := &TriageModule{
				ShodanKey:    shodanKey,
				shodanClient: shodanClient,
			}

			// Mock/patch GetServicesForHost function
			patches = append(patches, ApplyMethod(reflect.TypeOf(shodanClient), "GetServicesForHost", func(c *shodan.Client, ctx context.Context, ip string, options *shodan.HostServicesOptions) (*shodan.Host, error) {
				return ShodanHost.ShodanHost, nil
			}))

			// Mock function input
			ips := make(map[string]*net.IP)
			ipParsed := net.ParseIP("132.148.54.224")
			if ipParsed != nil {
				ips["Mock IP"] = &ipParsed
			}

			actualShodanHosts := m.GetServicesForIPs(ctx1, ips)

			So(actualShodanHosts, ShouldResemble, expectedShodanHosts)
		})
	})
}
