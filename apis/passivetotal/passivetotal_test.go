package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"encoding/csv"
	"io"

	. "github.com/agiledragon/gomonkey/v2"
	pt "github.com/gdcorp-infosec/threat-api/apis/passivetotal/passivetotalLibrary"
	. "github.com/smartystreets/goconvey/convey"
)

func TestDumpPDNSCSV(t *testing.T) {

	Convey("dumpPDNSCSV", t, func() {
		// setup stubs\mocks
		patches := []*Patches{}
		actualCSVResp := &bytes.Buffer{}

		// stub csv.Writer instance creation and point to it, cause it is needed to manipulate in tests
		patches = append(patches, ApplyFunc(csv.NewWriter, func(w io.Writer) *csv.Writer {
			actualCSVResp = w.(*bytes.Buffer)
			return nil
		}))
		// stub Write method of csv.Writer to prevent it to be called and fake it, use "reflect" to get to it's signature
		var count = 0
		var actualCSVHeaders []string
		patches = append(patches, ApplyMethod(reflect.TypeOf(&csv.Writer{}), "Write", func(_ *csv.Writer, headers  []string) error {
			if count == 0 {
				actualCSVHeaders = make([]string, len(headers))
  			copy(actualCSVHeaders, headers) // trying to catch headers to test them later
				count++
			}
			return nil
		}))
		// stub Flush method of csv.Writer to prevent it to be called and fake it, use "reflect" to get to it's signature
		expectedResult := "I_am_result_of_dumpPDNSCSV"
		patches = append(patches, ApplyMethod(reflect.TypeOf(&csv.Writer{}), "Flush", func(_ *csv.Writer) {
			actualCSVResp.WriteString(expectedResult)
		}))

		// deferred reset all stubs\mocks after every test suite running
		for _, patch := range patches {
			defer patch.Reset()
		}


		// prepare big input data for function under testing
		byt := []byte(`{
			"totalRecords": 1,
			"firstSeen": "firstSeen",
			"lastSeen": "lastSeen",
			"results": [
				{
					"firstSeen": "firstSeen",
					"lastSeen": "lastSeen",
					"resolveType": "resolveType",
					"value": "value",
					"recordHash": "recordHash",
					"resolve": "resolve",
					"source": ["source1", "source2"],
					"recordType": "recordType",
					"collected": "collected"
				}
			],
			"queryType": "queryType",
			"queryValue": "queryValue"
		}`)
		var pdnsReport pt.PDNSReport
		err := json.Unmarshal(byt, &pdnsReport)
		if err != nil {
			panic(err)
		}
		ptPDNSResults := map[string]*pt.PDNSReport{}
		ptPDNSResults["record1"] = &pdnsReport

		// call actual function under test
		result := dumpPDNSCSV(ptPDNSResults)

		Convey("should return correct output of formatted report", func() {
			So(result, ShouldEqual, actualCSVResp.String())
		})

		Convey("should set proper headers for CSV output", func() {
			expectedHeaders := []string{
				"Domain/IP",
				"FirstSeen",
				"ResolveType",
				"Value",
				"RecordHash",
				"LastSeen",
				"Resolve",
				"Source",
				"RecordType",
				"Collected",
			}
			So(actualCSVHeaders, ShouldResemble, expectedHeaders)
		})
	})
}
