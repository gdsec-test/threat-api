package main

import (
	"context"
	"net"
	"net/http"
	"reflect"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/ns3777k/go-shodan/v4/shodan"
	. "github.com/smartystreets/goconvey/convey"
)

func TestResolveDomains(t *testing.T) {

	Convey("resolveDomains", t, func() {
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

		Convey("Should resolve input domains", func() {

			expectedResolvedIPs := make(map[string]*net.IP)
			ipParsed := net.ParseIP("132.148.54.224")
			if ipParsed != nil {
				expectedResolvedIPs["Mock IP"] = &ipParsed
			}

			// mock Shodan client
			patches = append(patches, ApplyFunc(shodan.NewClient, func(client *http.Client, token string) *shodan.Client {
				return &shodan.Client{
					Token:          token,
					BaseURL:        "Mock base",
					ExploitBaseURL: "Mock exploit",
					StreamBaseURL:  "Mock stream base",
					Client:         client,
				}
			}))

			// mock input triage module struct
			shodanKey := "Mock shodan key"
			shodanClient := shodan.NewClient(nil, shodanKey)
			m := &TriageModule{
				ShodanKey:    shodanKey,
				shodanClient: shodanClient,
			}

			// mock/patch GetDNSResolve function
			patches = append(patches, ApplyMethod(reflect.TypeOf(shodanClient), "GetDNSResolve", func(c *shodan.Client, ctx context.Context, hostnames []string) (map[string]*net.IP, error) {
				return expectedResolvedIPs, nil
			}))

			// slice of mock input IPs
			inputIps := []string{"Mock IP"}

			actualResolvedIPs := m.resolveDomains(ctx1, inputIps)

			So(actualResolvedIPs, ShouldResemble, expectedResolvedIPs)
		})
	})
}
