package main

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	. "net/http"
	"net/url"
	"testing"

	"golang.org/x/net/context/ctxhttp"

	. "github.com/agiledragon/gomonkey/v2"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/smartystreets/goconvey/convey"
)

func TestQueryApi(t *testing.T) {

	Convey("QueryApi", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()
		actualURL := ""
		responseReportString := `{
			}`

		URLHausResponseBody := ioutil.NopCloser(bytes.NewBufferString(responseReportString))
		URLHausResp := &Response{
			StatusCode: http.StatusOK,
			Body:       URLHausResponseBody,
		}

		patches = append(patches, ApplyFunc(ctxhttp.PostForm, func(ctx context.Context, client *http.Client, url string, data url.Values) (*http.Response, error) {
			actualURL = url
			return URLHausResp, nil
		}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should successfully request from URLHaus API", func() {
			ExpectedURLHausResponseData := []byte(responseReportString)
			APIUrl := "I am API URL 5234856723df"
			URLHausProp := "super prop2345"
			URLHausValue := "super value gw342345"
			actualResponse, _ := QueryApi(ctx1, APIUrl, URLHausProp, URLHausValue)
			So(actualResponse, ShouldResemble, ExpectedURLHausResponseData)
			So(actualURL, ShouldResemble, APIUrl)
		})

		Convey("should return error if something goes wrong", func() {
			expectedError := errors.New("query api error g256")
			patches = append(patches, ApplyFunc(ctxhttp.PostForm, func(ctx context.Context, client *http.Client, url string, data url.Values) (*http.Response, error) {
				return nil, expectedError
			}))
			_, actualErr := QueryApi(ctx1, "bw345gbgw45h", "dfg", "bw45g5")
			So(actualErr, ShouldResemble, expectedError)
		})

	})
}
