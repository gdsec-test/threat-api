package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/smartystreets/goconvey/convey"
)

func TestGetMd5(t *testing.T) {

	Convey("GetMd5", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()

		responseReportString := `{
				"query_status": "ok",
				"md5_hash": "md5_hashdfg3w54g",
				"sha256_hash": "sha256_hashvw3q4t",
				"file_type": "file_type2vwe",
				"file_size": "243",
				"signature": "signaturevw4",
				"first_seen": "first_seen22345",
				"last_seen": "last_seenwer",
				"url_count": "34",
				"urlhaus_download": "urlhaus_downloadwerf4",
				"imphash": "imphash3245f",
				"ssdeep": "ssdeepvw5435",
				"tlsh": "tlshw3fwe",
				"virustotal": [ {
					"result": "resultr34fcwer",
					"percent": "43",
					"link": "linkwerf3"
				}],
				"urls": [{
					"url": "urlvw34",
					"url_status": "url_statusfvw34",
					"urlhaus_reference": "urlhaus_referencev2w345t",
					"filename": "filenamevw4t",
					"firstseen": "firstseenfvfw34",
					"lastseen": "lastseenfw23434r"
				}]
			}`

		URLHausResponseBody := []byte(responseReportString)
		URLHausUrl := ""
		URLHausKey := ""
		URLHausValue := ""
		patches = append(patches, ApplyFunc(QueryApi, func(ctx context.Context, apiUrl string, key string, value string) ([]byte, error) {
			URLHausUrl = apiUrl
			URLHausKey = key
			URLHausValue = value
			return URLHausResponseBody, nil
		}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should successfully request from URLHaus API", func() {
			ExpectedURLHausResponseData := &UrlhausPayloadEntry{}
			json.Unmarshal(URLHausResponseBody, &ExpectedURLHausResponseData)
			actualResponse, _ := GetMd5(ctx1, "some value")
			So(actualResponse, ShouldResemble, ExpectedURLHausResponseData)

		})

		type TestAPICall struct {
			Name       string
			Url        string
			Prop       string
			Value      string
			Method     func(ctx context.Context, value string) (*UrlhausPayloadEntry, error)
			MethodHost func(ctx context.Context, value string) (*UrlhausHostEntry, error)
			MethodUrl  func(ctx context.Context, value string) (*UrlhausUrlEntry, error)
		}

		expectedResults := []*TestAPICall{}

		expectedResults = append(expectedResults, &TestAPICall{
			"Md5 Call",
			apiHashUrl,
			"md5_hash",
			"md5_hash value 23425345",
			GetMd5,
			nil,
			nil,
		})

		expectedResults = append(expectedResults, &TestAPICall{
			"Sha256 Call",
			apiHashUrl,
			"sha256_hash",
			"sha256 hash value gw456",
			GetSha256,
			nil,
			nil,
		})

		expectedResults = append(expectedResults, &TestAPICall{
			"host Call",
			apiHostUrl,
			"host",
			"host value gw456fw34",
			nil,
			GetDomainOrIp,
			nil,
		})

		expectedResults = append(expectedResults, &TestAPICall{
			"url Call",
			apiUrlUrl,
			"url",
			"url value gw45vwerv6fw34",
			nil,
			nil,
			GetUrl,
		})

		for _, expectedResult := range expectedResults {
			Convey("should successfully do "+expectedResult.Name+" from URLHaus API", func() {
				if expectedResult.Url == apiHashUrl {
					expectedResult.Method(ctx1, expectedResult.Value)
				} else if expectedResult.Url == apiHostUrl {
					expectedResult.MethodHost(ctx1, expectedResult.Value)
				} else if expectedResult.Url == apiUrlUrl {
					expectedResult.MethodUrl(ctx1, expectedResult.Value)
				}
				So(URLHausUrl, ShouldResemble, expectedResult.Url)
				So(URLHausKey, ShouldResemble, expectedResult.Prop)
				So(URLHausValue, ShouldResemble, expectedResult.Value)
			})

			Convey("should return error for "+expectedResult.Name+"if something goes wrong", func() {
				expectedError := errors.New("query api error for " + expectedResult.Name)
				QueryApiStub := ApplyFunc(QueryApi, func(ctx context.Context, apiUrl string, key string, value string) ([]byte, error) {
					return nil, expectedError
				})
				var actualErr error
				if expectedResult.Url == apiHashUrl {
					_, actualErr = expectedResult.Method(ctx1, expectedResult.Value)
				} else if expectedResult.Url == apiHostUrl {
					_, actualErr = expectedResult.MethodHost(ctx1, expectedResult.Value)
				} else if expectedResult.Url == apiUrlUrl {
					_, actualErr = expectedResult.MethodUrl(ctx1, expectedResult.Value)
				}
				So(actualErr, ShouldResemble, expectedError)
				QueryApiStub.Reset()
			})
		}

	})
}
