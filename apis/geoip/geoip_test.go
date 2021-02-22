package main

import (
	"context"
	"testing"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

func TestLookup(t *testing.T) {

	ctx := context.Background()
	toolbox := toolbox.GetToolbox()
	defer toolbox.Close(ctx)

	testIP := "72.210.63.111"
	triageRequest := &triage.Request{
		IOCs:     []string{testIP},
		IOCsType: triage.IPType,
	}
	triageModule := TriageModule{}
	triageResult, err := triageModule.Triage(ctx, triageRequest)
	if err != nil {
		t.Fatal(err)
	}
	toolbox.Close(ctx)

	if len(triageResult) == 0 {
		t.Fatal("len 0")
	}
	if triageResult[0].Data == "" {
		t.Fatal("first data element empty ")
	}
}