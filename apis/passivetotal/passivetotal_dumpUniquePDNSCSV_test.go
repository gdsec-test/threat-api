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

func TestDumpUniquePDNSCSV(t *testing.T) {

	Convey("dumpUniquePDNSCSV", t, func() {
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
			if count == 0 {
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
		expectedResult := "I_am_result_of_dumpUniquePDNSCSV"
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
			"total": 1,
			"frequency": [[1, 2], [3, 4]],
			"results": [ "result1456", "result762" ],
			"queryType": "I_AM_queryType4234",
			"queryValue": "I_AM_queryValue695"
		}`)
		var pdnsReport pt.PDNSUniqueReport
		err := json.Unmarshal(byt, &pdnsReport)
		if err != nil {
			panic(err)
		}
		ptPDNSResults := map[string]*pt.PDNSUniqueReport{}
		ptPDNSResults["record1"] = &pdnsReport

		Convey("should return correct output of formatted report", func() {
			// call actual function under test
			result := dumpUniquePDNSCSV(ptPDNSResults)
			So(result, ShouldEqual, actualCSVResp.String())
		})

		Convey("should set proper headers for CSV output", func() {
			// call actual function under test
			dumpUniquePDNSCSV(ptPDNSResults)
			expectedHeaders := []string{
				"Domain/IP",
				"Result",
				"Frequency",
			}
			So(actualCSVHeaders, ShouldResemble, expectedHeaders)
		})

		Convey("should set proper results in CSV Rows for output", func() {
			// call actual function under test
			dumpUniquePDNSCSV(ptPDNSResults)
			expectedCsvResultsRow := []string{
				"record1",
				"3",
				"4",
			}
			So(csvResultsRow, ShouldResemble, expectedCsvResultsRow)
		})

	})
}
