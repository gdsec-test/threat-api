package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/url"
	"reflect"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"

	sn "github.com/gdcorp-infosec/threat-api/apis/servicenow/servicenowLibrary"
	. "github.com/smartystreets/goconvey/convey"
)

func TestCmdbHostname(t *testing.T) {

	Convey("CmdbHostname", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()
		IOCs := []string{"github-actions.cloud.phx3.gdg"}
		snUrl := "I am URL for Srvice NOW API g25g"
		snUser := "I am User for Srvice NOW API bw45g"
		snPass := "I am Password for Srvice NOW API vw34ng"
		snTableName := "cmdb_ci"
		SNClient, _ := sn.New(snUrl, snUser, snPass, snTableName)
		triageModule := TriageModule{
			SNClient: SNClient,
		}
		actualQuery := ""
		var actualURLValues url.Values
		// var actualRows chan sn.Row

		patches = append(patches, ApplyMethod(reflect.TypeOf(SNClient), "GetRows", func(client *sn.Client, ctx context.Context, query string, additionalURLValues url.Values, rows chan sn.Row) error {
			actualQuery = query
			actualURLValues = additionalURLValues
			// actualRows = rows
			ServiceNowResponseBody := ioutil.NopCloser(bytes.NewBufferString(`{
				"result": [{"sys_id":"b9ed1340db0233000514fe1b68961949"}]
			}`))
			results := sn.RowsResponse{}
			decoder := json.NewDecoder(ServiceNowResponseBody)
			err := decoder.Decode(&results)
			if err != nil {
				return nil
			}
			for _, entry := range results.Result {
				rows <- sn.Row(entry)
			}
			close(rows)
			return nil
		}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should make proper request for CMDB host names", func() {
			query := "fqdn=github-actions.cloud.phx3.gdg"
			triageModule.GetCMDBData(ctx1, IOCs)
			So(actualQuery, ShouldResemble, query)
			So(actualURLValues, ShouldResemble, url.Values{
				"sysparm_fields": []string{"assignment_group,support_group"},
			})
		})

	})
}
