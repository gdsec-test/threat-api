package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	. "github.com/agiledragon/gomonkey/v2"
	pt "github.com/gdcorp-infosec/threat-api/apis/passivetotal/passivetotalLibrary"
	. "github.com/smartystreets/goconvey/convey"
	"io"
	"reflect"
	"testing"
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
		var csvResultsRow []string
		patches = append(patches, ApplyMethod(reflect.TypeOf(&csv.Writer{}), "Write", func(_ *csv.Writer, rowValues []string) error {
			if count == 0 { // counts calls to Write method
				actualCSVHeaders = make([]string, len(rowValues))
				copy(actualCSVHeaders, rowValues) // trying to catch headers to test them later
			} else {
				csvResultsRow = make([]string, len(rowValues))
				copy(csvResultsRow, rowValues) // trying to catch csvResults row to test them later
			}
			count++
			return nil
		}))
		// stub Flush method of csv.Writer to prevent it to be called and fake it, use "reflect" to get to it's signature
		expectedResult := "I_am_result_of_dumpPDNSCSV"
		patches = append(patches, ApplyMethod(reflect.TypeOf(&csv.Writer{}), "Flush", func(_ *csv.Writer) {
			actualCSVResp.WriteString(expectedResult)
		}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		// prepare big input data for function under testing
		byt := []byte(`{
			"totalRecords": 1,
			"firstSeen": "firstSeen",
			"lastSeen": "lastSeen",
			"results": [
				{
					"firstSeen": "I_AM_firstSeen560",
					"lastSeen": "I_AM_lastSeen404",
					"resolveType": "I_AM_resolveType367",
					"value": "I_AM_value3456",
					"recordHash": "I_AM_recordHash93345",
					"resolve": "I_AM_resolve345",
					"source": ["I_AM_source1245", "I_AM_source22347"],
					"recordType": "I_AM_recordType4256",
					"collected": "I_AM_collected0393"
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

		Convey("should return correct output of formatted report", func() {
			// call actual function under test
			result := dumpPDNSCSV(ptPDNSResults)
			So(result, ShouldEqual, actualCSVResp.String())
		})

		Convey("should set proper headers for CSV output", func() {
			// call actual function under test
			dumpPDNSCSV(ptPDNSResults)
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

		Convey("should set proper results in CSV Rows for output", func() {
			// call actual function under test
			dumpPDNSCSV(ptPDNSResults)
			expectedCsvResultsRow := []string{
				"record1",
				"I_AM_firstSeen560",
				"I_AM_resolveType367",
				"I_AM_value3456",
				"I_AM_recordHash93345",
				"I_AM_lastSeen404",
				"I_AM_resolve345",
				"I_AM_source1245 I_AM_source22347",
				"I_AM_recordType4256",
				"I_AM_collected0393",
			}
			So(csvResultsRow, ShouldResemble, expectedCsvResultsRow)
		})

	})
}
