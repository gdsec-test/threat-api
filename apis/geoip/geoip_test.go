package main

import (
	"context"
	"fmt"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
	"github.com/gdcorp-infosec/threat-util/lambda/toolbox"
	"os"
	"testing"
)

func TestLookup(t *testing.T) {

	fmt.Println(os.Getenv("ELASTIC_APM_SERVICE_NAME"))
	ctx := context.Background()
	toolbox := toolbox.GetToolbox()
	defer toolbox.Close(ctx)

	triageRequest := &triage.Request{
		IOCs:     []string{"72.210.63.111"},
		IOCsType: triage.IPType,
	}
	triageModule := TriageModule{}
	triageResult, err := triageModule.Triage(ctx, triageRequest)
	toolbox.Close(ctx)

	if len(triageResult) == 0 {
		t.Fatal("len 0")
	}

	if triageResult[0].Data == "" {
		t.Fatal("first data element empty ")
	}
	// TODO: assert triageResult
	if err != nil {
		t.Fatal(err)
	}
}
