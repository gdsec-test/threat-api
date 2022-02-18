package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"testing"
	"time"

	. "github.com/agiledragon/gomonkey/v2"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/smartystreets/goconvey/convey"
)

func TestGetJobProgress(t *testing.T) {

	Convey("getJobProgress", t, func() {
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()
		to = toolbox.GetToolbox()

		startTime := float64(time.Now().Unix())
		var jobDB *common.JobDBEntry
		var TestJobEntryData = `{
			"jobId": "Some job ID 345234",
			"startTime": ` + fmt.Sprintf("%f", startTime) + `,
			"requestedModules": ["apivoid", "urlscanio"],
			"submission": {},
			"responses": {
				"apivoid": [
					{
						"data": {}
					}
				]
			}
		}`
		json.Unmarshal([]byte(TestJobEntryData), &jobDB)
		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
			to = nil
		})

		Convey("should successfully get jobs progress for half jobs done", func() {
			actualJobStatus, actualPercentage, _ := getJobProgress(ctx1, jobDB)
			So(actualJobStatus, ShouldResemble, JobInProgress)
			So(actualPercentage, ShouldEqual, 0.5)
		})

		Convey("should count failed job as finished", func() {
			TestJobEntryData = `{
				"jobId": "Some job ID 345234",
				"startTime": ` + fmt.Sprintf("%f", startTime) + `,
				"requestedModules": ["apivoid", "urlscanio", "recordedfuture", "url"],
				"submission": {},
				"responses": {
					"apivoid": [
						{
							"data": {}
						}
					],
					"recordedfuture": [
						{
							"data": {}
						}
					],
					"urlscanio": [
						{
							"data": {},
							"error": "I am error"
						}
					]
				}
			}`
			json.Unmarshal([]byte(TestJobEntryData), &jobDB)
			actualJobStatus, actualPercentage, _ := getJobProgress(ctx1, jobDB)
			So(actualJobStatus, ShouldResemble, JobInProgress)
			So(actualPercentage, ShouldResemble, 0.75)
		})

		Convey("should timeout if response is not received within 15 minutes", func() {
			oldTime := time.Now().Add(-time.Minute * 30)
			startTime := float64(oldTime.Unix())
			TestJobEntryData = `{
				"jobId": "Some job ID 345234",
				"startTime": ` + fmt.Sprintf("%f", startTime) + `,
				"requestedModules": ["apivoid", "urlscanio"],
				"submission": {},
				"responses": {
				}
			}`
			json.Unmarshal([]byte(TestJobEntryData), &jobDB)
			actualJobStatus, actualPercentage, _ := getJobProgress(ctx1, jobDB)
			So(actualJobStatus, ShouldResemble, JobIncomplete)
			So(math.Round(actualPercentage), ShouldEqual, math.Round(1))
		})

		Convey("should finish as completed when all jobs completed", func() {
			TestJobEntryData = `{
				"jobId": "Some job ID 345234",
				"startTime": ` + fmt.Sprintf("%f", startTime) + `,
				"requestedModules": ["apivoid", "urlscanio", "recordedfuture"],
				"submission": {},
				"responses": {
					"apivoid": [
						{
							"data": {}
						}
					],
					"recordedfuture": [
						{
							"data": {}
						}
					],
					"urlscanio": [
						{
							"data": {}
						}
					]
				}
			}`
			json.Unmarshal([]byte(TestJobEntryData), &jobDB)
			actualJobStatus, actualPercentage, _ := getJobProgress(ctx1, jobDB)
			So(actualJobStatus, ShouldResemble, JobCompleted)
			So(math.Round(actualPercentage), ShouldEqual, math.Round(1))
		})

	})
}
