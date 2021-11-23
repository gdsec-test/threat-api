package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"reflect"
	. "github.com/agiledragon/gomonkey/v2"
	pt "github.com/gdcorp-infosec/threat-api/apis/passivetotal/passivetotalLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
	. "github.com/smartystreets/goconvey/convey"
)

func TestGetPassiveDNS(t *testing.T) {

	Convey("GetPassiveDNS", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		loggingSpan := &appsectracing.Span{}
		ctx1 := context.Background()
		// stub TracerLogger.StartSpan instance creation and point to it, cause it is needed to manipulate in tests
		patches = append(patches, ApplyFunc(tb.TracerLogger.StartSpan,
		 		func(ctx context.Context, operationName, operationType, operationSubType, operationAction string) (*appsectracing.Span, context.Context) {
			return loggingSpan, ctx
		}))

		// stub Span.AddError
		patches = append(patches, ApplyMethod(reflect.TypeOf(loggingSpan), "AddError", func(_ *appsectracing.Span, err error) {}))

		// stub Span.End
		var isLoggerEndCalled = false
		patches = append(patches, ApplyMethod(reflect.TypeOf(loggingSpan), "End", func(_ *appsectracing.Span, ctx context.Context) {
			isLoggerEndCalled = true
		}))

		report1 := `{
			"totalRecords": 1,
			"firstSeen": "firstSeen",
			"lastSeen": "lastSeen",
			"results": [
				{
					"firstSeen": "I_AM_firstSeen4560",
					"lastSeen": "I_AM_lastSeen0784",
					"resolveType": "I_AM_resolveType30890",
					"value": "I_AM_value-896",
					"recordHash": "I_AM_recordHash99095",
					"resolve": "I_AM_resolve4565",
					"source": ["I_AM_source746745", "I_AM_source2-8907"],
					"recordType": "I_AM_recordType42745656",
					"collected": "I_AM_collected085673"
				}
			],
			"queryType": "queryType",
			"queryValue": "queryValue"
		}`
		var reportHolder *pt.PDNSReport
		json.Unmarshal([]byte(report1), &reportHolder)
		// stub pt.GetPassiveDNS and point to it, cause it is needed to manipulate in tests
		patches = append(patches, ApplyFunc(pt.GetPassiveDNS, func(ctx context.Context, ptUrl string, ioc string, user string,
				key string, PTClient *http.Client) (*pt.PDNSReport, error) {
			return reportHolder, nil
		}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		// prepare input data for function under testing
		triageRequest := triage.Request{
			IOCs: []string{"I_m_IOC312"},
			IOCsType: "IP",
			JWT: "superJWT",
			Verbose: true,
		}

		triageModule := &TriageModule{}

		Convey("should set proper output result report", func() {
			// call actual function under test
			report, _ := triageModule.GetPassiveDNS(ctx1, &triageRequest)
			byt := []byte(`{
				"I_m_IOC312": ` + report1 +`
			}`)
			var pdnsReport map[string]*pt.PDNSReport
			err := json.Unmarshal(byt, &pdnsReport)
			if err != nil {
				panic(err)
			}
			So(pdnsReport, ShouldResemble, report)
		})

		Convey("should finish logging by the end of report", func() {
			// call actual function under test
			triageModule.GetPassiveDNS(ctx1, &triageRequest)
			So(isLoggerEndCalled, ShouldResemble, true)
		})


	})
}
