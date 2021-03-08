package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

func TestEnrichCVE(t *testing.T) {

	ctx := context.Background()
	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	var triageRequests []*triage.Request
	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"CVE-2014-0160", "CVE-2010-2568"},
		IOCsType: triage.CVEType,
	})

	start := time.Now()

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

	duration := time.Since(start)
	fmt.Printf("--------- Time for CVE ---------")
	fmt.Println(duration)

}
