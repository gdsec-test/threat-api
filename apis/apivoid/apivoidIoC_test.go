package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

func TestGetAPIVoidData(t *testing.T) {

	ctx := context.Background()
	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	var triageRequests []*triage.Request
	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"https://www.twitter.com/"},
		IOCsType: triage.URLType,
	})
	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"google.com"},
		IOCsType: triage.DomainType,
	})
	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"67.72.153.231"},
		IOCsType: triage.IPType,
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
		for _, data := range triageResult[0].Metadata {
			fmt.Println(data)
		}

	}
}
