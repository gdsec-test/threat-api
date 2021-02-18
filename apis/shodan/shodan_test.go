package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

func TestGetServicesForIPs(t *testing.T) {

	ctx := context.Background()
	toolbox := toolbox.GetToolbox()
	defer toolbox.Close(ctx)

	//testIP := "164.128.164.119"
	triageRequest := &triage.Request{
		IOCs:     []string{"72.210.63.111", "164.128.164.119", "93.90.222.20"},
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

	fmt.Println("-------------------- Metadata -------------------------")
	for _, data := range triageResult[0].Metadata {
		fmt.Println(data)
	}
	fmt.Println("-------------------- Data -------------------------")
	fmt.Println(triageResult[0].Data)
}
