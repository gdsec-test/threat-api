package main

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

func TestTriage(t *testing.T) {
	ctx := context.Background()

	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	triageModule, err := initCMAPModule(ctx)
	if err != nil {
		t.Fatal(err)
	}

	triageRequests := []*triage.Request{
		{IOCs: []string{"godaddy.com"}, IOCsType: triage.DomainType, JWT: os.Getenv("TESTING_JWT")},
	}

	for i, triageRequest := range triageRequests {
		data, err := triageModule.Triage(ctx, triageRequest)
		if err != nil {
			t.Errorf("test %d failed: %v", i, err)
			continue
		}
		if len(data) == 0 {
			t.Errorf("test %d failed, no data returned", i)
		}
		fmt.Printf("Job finished: %s, metadata: %s, data: %s\n", data[0].Title, data[0].Metadata, data[0].Data)
	}
}
