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

func TestEnrichHASHGo(t *testing.T) {

	Convey("EnrichHASH", t, func() {
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
		RecordedFutureHashResponseBody := ioutil.NopCloser(bytes.NewBufferString(TestRecorderFutureHASHReportData))
		RecordedFutureHashClient := http.DefaultClient
		RecordedFutureHashResp := &Response{
			StatusCode: http.StatusOK,
			Body: RecordedFutureHashResponseBody,
		}
		patches = append(patches, ApplyMethod(reflect.TypeOf(RecordedFutureHashClient), "Do", func(client *http.Client, req *Request) (*Response, error) {
			return RecordedFutureHashResp, nil
		}))

		RecordedFutureHashKey := "RF_key_wert"

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should return proper output result report", func() {
			RecordedFutureHashReportData := &rt.HashReport{}
			json.Unmarshal([]byte(TestRecorderFutureHASHReportData), &RecordedFutureHashReportData)

			actualReport, _ := rt.EnrichHASH(ctx1, RecordedFutureHashKey, RecordedFutureHashClient, "010000000000000000000000111", rt.HASHReportFields, false)
			So(RecordedFutureHashReportData, ShouldResemble, actualReport)
		})

		Convey("should set proper URL and request params", func() {
			RecordedFutureHashKey = "I_changed_to_agw345gsdf"
			hash := "010000000000000000000000111"
			hashEndpoint := "https://api.recordedfuture.com/v2/hash/"
			values := url.Values{}
			values.Add("fields", strings.Join(rt.HASHReportFields, ","))
			values.Add("metadata", fmt.Sprintf("%v", false))
			expectedURL := fmt.Sprintf("%s%v?%s", hashEndpoint, hash, values.Encode())
			rt.EnrichHASH(ctx1, RecordedFutureHashKey, RecordedFutureHashClient, hash, rt.HASHReportFields, false)
			So(actualURL, ShouldResemble, expectedURL)
			So(requestMethod, ShouldResemble, http.MethodGet)
			So(request.Header.Get("X-RFToken"), ShouldResemble, RecordedFutureHashKey)
		})

		Convey("should return error as output result if something goes wrong", func() {
			RecordedFutureHashResp.StatusCode = http.StatusForbidden
			_, err := rt.EnrichHASH(ctx1, RecordedFutureHashKey, RecordedFutureHashClient, "010000000000000000000000111", rt.HASHReportFields, false)
			So(err, ShouldResemble, fmt.Errorf("bad status code: %d", RecordedFutureHashResp.StatusCode))
		})

	})
}
