// +build !runTests

package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

func TestWebQueriesResults(t *testing.T) {
	ctx := context.Background()
	tb := toolbox.GetToolbox()
	defer tb.Close(ctx)

	var triageRequests []*triage.Request
	triageRequests = append(triageRequests, &triage.Request{
		// Confickr
		IOCs:     []string{"574cf0062911c8c4eca2156187b8207d"},
		IOCsType: triage.MD5Type,
	})
	triageRequests = append(triageRequests, &triage.Request{
		// Confickr
		IOCs:     []string{"1023aeeee1dd4ca115fcb8e4882f9d5a1815dcecd2d7f35042110f96957127a0"},
		IOCsType: triage.SHA256Type,
	})
	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"http://sskymedia.com/VMYB-ht_JAQo-gi/INV/99401FORPO/20673114777/US/Outstanding-Invoices/", "http://45.61.49.78/razor/r4z0r.mips", "http://178.175.28.140:49228/Mozi.m"},
		IOCsType: triage.URLType,
	})
	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"hn.kd.ny.adsl", "stumbletrouser.com"},
		IOCsType: triage.DomainType,
	})
	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"123.130.169.124", "192.3.152.166"},
		IOCsType: triage.IPType,
	})

	// this test expects the API key to be the online line in a
	// test file named "vtapi.txt" in the same directory as this
	// code
	data, err := ioutil.ReadFile("vtapi.txt")
	if err != nil {
		panic(err)
	}
	apiKey := string(data)

	for i, triageRequest := range triageRequests {
		fmt.Printf("Triage request test %d\n", i)

		triageModule := TriageModule{}
		triageResult, err := triageModule.ProcessRequest(ctx, triageRequest, apiKey)
		if err != nil {
			t.Fatal(err)
		}

		csv := csv.NewReader(strings.NewReader(triageResult.Data))
		records, _ := csv.ReadAll()
		// the header always counts as one record
		if len(records) < 2 {
			t.Fail()
		}
	}
}

func TestWebQueriesNoResults(t *testing.T) {
	ctx := context.Background()
	tb := toolbox.GetToolbox()
	defer tb.Close(ctx)

	var triageRequests []*triage.Request
	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"574cf0062911c8c4eca2156187b8207F"},
		IOCsType: triage.MD5Type,
	})
	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"1023aeeee1dd4ca115fcb8e4882f9d5a1815dcecd2d7f35042110f96957127aF"},
		IOCsType: triage.SHA256Type,
	})
	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"http://sskymedia.com/VMYB-ht_JAQo-gi/INV/99401FORPO/20673114777/US/nosuchpage/"},
		IOCsType: triage.URLType,
	})
	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"nositehere.zzz"},
		IOCsType: triage.DomainType,
	})
	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"127.0.0.1"},
		IOCsType: triage.IPType,
	})

	// this test expects the API key to be the online line in a
	// test file named "vtapi.txt" in the same directory as this
	// code
	data, err := ioutil.ReadFile("vtapi.txt")
	if err != nil {
		panic(err)
	}
	apiKey := string(data)

	for i, triageRequest := range triageRequests {
		fmt.Printf("Triage request test %d\n", i)

		triageModule := TriageModule{}
		triageResult, err := triageModule.ProcessRequest(ctx, triageRequest, apiKey)
		if err != nil {
			t.Fatal(err)
		}

		csv := csv.NewReader(strings.NewReader(triageResult.Data))
		records, _ := csv.ReadAll()
		// the header always counts as one record
		if len(records) > 2 {
			t.Fail()
		}
	}
}
