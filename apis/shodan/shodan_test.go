package main

import (
	"context"
	"testing"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

func TestGetServicesForIPs(t *testing.T) {

	ctx := context.Background()
	toolboxTmp = toolbox.GetToolbox()
	defer toolboxTmp.Close(ctx)

	var triageRequests []*triage.Request
	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"72.210.63.111", "164.128.164.119", "93.90.222.20"},
		IOCsType: triage.IPType,
	})
	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"etbnaman.com", "gacetaeditorial.com"},
		IOCsType: triage.DomainType,
	})

	for _, triageRequest := range triageRequests {
		triageModule := TriageModule{}
		triageResult, err := triageModule.Triage(ctx, triageRequest)
		if err != nil {
			t.Fatal(err)
		}

		if len(triageResult) == 0 {
			t.Fatal("len 0")
		}
		if triageResult[0].Data == "" {
			t.Fatal("first data element empty ")
		}
	}
}
