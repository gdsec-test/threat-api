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

func TestEnrichIPGo(t *testing.T) {

	Convey("EnrichIP", t, func() {
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
		RecordedFutureIPResponseBody := ioutil.NopCloser(bytes.NewBufferString(TestRecorderFutureIPReportData))
		RecordedFutureIPClient := http.DefaultClient
		RecordedFutureIPResp := &Response{
			StatusCode: http.StatusOK,
			Body: RecordedFutureIPResponseBody,
		}
		patches = append(patches, ApplyMethod(reflect.TypeOf(RecordedFutureIPClient), "Do", func(client *http.Client, req *Request) (*Response, error) {
			return RecordedFutureIPResp, nil
		}))

		RecordedFutureIPKey := "RF_key_343456eg5"

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should return proper output result report", func() {
			RecordedFutureIPReportData := &rt.IPReport{}
			json.Unmarshal([]byte(TestRecorderFutureIPReportData), &RecordedFutureIPReportData)

			actualReport, _ := rt.EnrichIP(ctx1, RecordedFutureIPKey, RecordedFutureIPClient, "23.52.152.75", rt.IPReportFields, false)
			So(RecordedFutureIPReportData, ShouldResemble, actualReport)
		})

		Convey("should set proper URL and request params", func() {
			RecordedFutureIPKey = "I_changed_to_anotherKey"
			ipAddress := "23.52.152.75"
			ipEndpoint := "https://api.recordedfuture.com/v2/ip/"
			values := url.Values{}
			values.Add("fields", strings.Join(rt.IPReportFields, ","))
			values.Add("metadata", fmt.Sprintf("%v", false))
			expectedURL := fmt.Sprintf("%s%v?%s", ipEndpoint, strings.ToUpper(ipAddress), values.Encode())
			rt.EnrichIP(ctx1, RecordedFutureIPKey, RecordedFutureIPClient, ipAddress, rt.IPReportFields, false)
			So(actualURL, ShouldResemble, expectedURL)
			So(requestMethod, ShouldResemble, http.MethodGet)
			So(request.Header.Get("X-RFToken"), ShouldResemble, RecordedFutureIPKey)
		})

		Convey("should return error as output result if something goes wrong", func() {
			RecordedFutureIPResp.StatusCode = http.StatusBadRequest
			_, err := rt.EnrichIP(ctx1, RecordedFutureIPKey, RecordedFutureIPClient, "23.52.152.75", rt.IPReportFields, false)
			So(err, ShouldResemble, fmt.Errorf("bad status code: %d", RecordedFutureIPResp.StatusCode))
		})

	})
}
