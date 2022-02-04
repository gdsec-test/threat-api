package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	. "net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"

	rt "github.com/gdcorp-infosec/threat-api/apis/recordedfuture/recordedfutureLibrary"
	. "github.com/smartystreets/goconvey/convey"
)

func TestEnrichCVEGo(t *testing.T) {

	Convey("EnrichCVE", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()

		request := Request{
			Header: Header{},
		}
		actualURL := ""
		requestMethod := ""
		patches = append(patches, ApplyFunc(http.NewRequestWithContext, func(ctx context.Context, method, url string, body io.Reader) (*Request, error) {
			actualURL = url
			requestMethod = method
			return &request, nil
		}))
		RecordedFutureCVEResponseBody := ioutil.NopCloser(bytes.NewBufferString(TestRecorderFutureCVEReportData))
		RecordedFutureCVEClient := http.DefaultClient
		RecordedFutureCVEResp := &Response{
			StatusCode: http.StatusOK,
			Body: RecordedFutureCVEResponseBody,
		}
		patches = append(patches, ApplyMethod(reflect.TypeOf(RecordedFutureCVEClient), "Do", func(client *http.Client, req *Request) (*Response, error) {
			return RecordedFutureCVEResp, nil
		}))

		RecordedFutureCVEKey := "RF_key_345"

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should return proper output result report", func() {
			RecordedFutureCVEReportData := &rt.CVEReport{}
			json.Unmarshal([]byte(TestRecorderFutureCVEReportData), &RecordedFutureCVEReportData)

			actualReport, _ := rt.EnrichCVE(ctx1, RecordedFutureCVEKey, RecordedFutureCVEClient, "CVE-2022", rt.CVEReportFields, false)
			So(RecordedFutureCVEReportData, ShouldResemble, actualReport)
		})

		Convey("should set proper URL and request params", func() {
			RecordedFutureCVEKey = "I_changed_to_anotherKey"
			cve := "CVE-2022-456"
			vulnerabilityEndpoint := "https://api.recordedfuture.com/v2/vulnerability/"
			values := url.Values{}
			values.Add("fields", strings.Join(rt.CVEReportFields, ","))
			values.Add("metadata", fmt.Sprintf("%v", false))
			expectedURL := fmt.Sprintf("%s%v?%s", vulnerabilityEndpoint, strings.ToUpper(cve), values.Encode())
			rt.EnrichCVE(ctx1, RecordedFutureCVEKey, RecordedFutureCVEClient, cve, rt.CVEReportFields, false)
			So(actualURL, ShouldResemble, expectedURL)
			So(requestMethod, ShouldResemble, http.MethodGet)
			So(request.Header.Get("X-RFToken"), ShouldResemble, RecordedFutureCVEKey)
		})

		Convey("should return error as output result if something goes wrong", func() {
			RecordedFutureCVEResp.StatusCode = http.StatusBadRequest
			_, err := rt.EnrichCVE(ctx1, RecordedFutureCVEKey, RecordedFutureCVEClient, "CVE-2022", rt.CVEReportFields, false)
			So(err, ShouldResemble, fmt.Errorf("bad status code: %d", RecordedFutureCVEResp.StatusCode))
		})

	})
}
