package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

func TestWebQueries(t *testing.T) {
	ctx := context.Background()
	tb := toolbox.GetToolbox()
	defer tb.Close(ctx)

	var triageRequests []*triage.Request
	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"f3a5fdb1e0e62eda7501823a97240e11"},
		IOCsType: triage.MD5Type,
	})
	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"f9311bfd0670d076900dd05f76dd9c1221904cda0e5b2e4d38d6b8656c8b7851"},
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

	apiKey := "2f2fa71c9de7f277f7d0da556d1882821488c038f2138985085df23be724b0f3"
	for i, triageRequest := range triageRequests {
		fmt.Printf("Triage request test %d\n", i)

		triageModule := TriageModule{}
		triageResult, err := triageModule.ProcessRequest(triageRequest, apiKey)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Println(triageResult.Title)

		/*
			if len(triageResult) == 0 {
				t.Fatal("len 0")
			}
			if triageResult[0].Data == "" {
				t.Fatal("first data element empty ")
			}
		*/
	}
}
