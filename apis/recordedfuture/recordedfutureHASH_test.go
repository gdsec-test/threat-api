package main

import (
	"context"
	"testing"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

func TestEnrichHASH(t *testing.T) {

	ctx := context.Background()
	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	var triageRequests []*triage.Request
	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"c625ff97e147e897468204e0e6ccd1aa", "938079b196c598bc43f97e0ecf128e77"},
		IOCsType: triage.MD5Type,
	})
	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"daed41395ba663bef2c52e3d1723ac46253a9008b582bb8d9da9cb0044991720"},
		IOCsType: triage.SHA256Type,
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
