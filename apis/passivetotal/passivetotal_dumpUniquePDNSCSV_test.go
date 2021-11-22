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
		patches = append(patches, ApplyMethod(reflect.TypeOf(&csv.Writer{}), "Write", func(_ *csv.Writer, headers  []string) error {
			if count == 0 {
				actualCSVHeaders = make([]string, len(headers))
  			copy(actualCSVHeaders, headers) // trying to catch headers to test them later
				count++
			}
			return nil
		}))
		// stub Flush method of csv.Writer to prevent it to be called and fake it, use "reflect" to get to it's signature
		expectedResult := "I_am_result_of_dumpUniquePDNSCSV"
		patches = append(patches, ApplyMethod(reflect.TypeOf(&csv.Writer{}), "Flush", func(_ *csv.Writer) {
			actualCSVResp.WriteString(expectedResult)
		}))

		Reset(func () {
		// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		// prepare big input data for function under testing
		byt := []byte(`{
			"total": 1,
			"frequency": [[1, 2], [3, 4]],
			"results": [ "result1", "result2" ],
			"queryType": "queryType",
			"queryValue": "queryValue"
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
	})
}
