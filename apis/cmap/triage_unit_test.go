package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"

	"reflect"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	"github.com/gdcorp-infosec/cmap-go/cmap"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
	. "github.com/smartystreets/goconvey/convey"
	"github.secureserver.net/go/sso-client/sso"
)

func TestUnitTriage(t *testing.T) {

	Convey("Triage", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()

		actualURL := ""
		cmapClient := cmap.Client{}
		actualCert := tls.Certificate{}
		var actualSSOEnv sso.Environment
		patches = append(patches, ApplyFunc(cmap.New, func(ctx context.Context, baseURL string, certificate tls.Certificate, ssoEnv sso.Environment) (*cmap.Client, error) {
			actualURL = baseURL
			actualCert = certificate
			actualSSOEnv = ssoEnv
			return &cmapClient, nil
		}))
		cmapTriageModule := TriageModule{}
		patches = append(patches, ApplyFunc(initCMAPModule, func(ctx context.Context) (*TriageModule, error) {
			return &cmapTriageModule, nil
		}))

		tlsCert := tls.Certificate{
			Certificate: [][]byte{
				{'1', '4', '6', '8'},
			},
		}
		patches = append(patches, ApplyFunc(tls.X509KeyPair, func(certPEMBlock, keyPEMBlock []byte) (tls.Certificate, error) {
			return tlsCert, nil
		}))

		patches = append(patches, ApplyMethod(reflect.TypeOf(tb), "Authorize", func(t *toolbox.Toolbox, ctx context.Context, jwt, action, resource string) (bool, error) {
			return true, nil
		}))
		triageModule, _ := initCMAPModule(ctx1)

		TestCMAPData := `{
			"DomainQuery": {
				"ShopperID": "someshopper"
			}
		}`
		var cmapQuery *cmap.DomainQuery
		err := json.Unmarshal([]byte(TestCMAPData), &cmapQuery)
		if err != nil {
			fmt.Println()
		}
		var actualDomain string
		patches = append(patches, ApplyMethod(reflect.TypeOf(triageModule), "DoDomainQuery", func(m *TriageModule, c *cmap.Client, ctx context.Context, domain string) (*cmap.DomainQuery, error) {
			actualDomain = domain
			return cmapQuery, nil
		}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should return proper output result report", func() {

			triageRequests := []*triage.Request{
				{IOCs: []string{"godaddy.com"}, IOCsType: triage.DomainType, JWT: os.Getenv("TESTING_JWT")},
			}
			for _, triageRequest := range triageRequests {
				report, _ := triageModule.Triage(ctx1, triageRequest)
				data := []*triage.Data{{Title: "GoDaddy Shopper Data", Metadata: []string{"1/1 domains are GoDaddy customer domains"}, DataType: triage.DataType(""), Data: "domain,shopper_id,first name,last name,address1,address2,city,state,postal code,country,domain status\n,someshopper,,,,,,,,,\n"}}
				So(report, ShouldResemble, data)
			}
		})

		Convey("should use proper request params", func() {

			triageRequests := []*triage.Request{
				{IOCs: []string{"godaddy.com"}, IOCsType: triage.DomainType, JWT: os.Getenv("TESTING_JWT")},
			}
			for _, triageRequest := range triageRequests {
				triageModule.Triage(ctx1, triageRequest)
			}
			So(actualURL, ShouldResemble, "https://cmapservice.int.godaddy.com/graphql")
			So(actualCert, ShouldResemble, tlsCert)
			So(actualSSOEnv, ShouldResemble, sso.Production)
			So(actualDomain, ShouldResemble, "godaddy.com")
		})

	})
}
