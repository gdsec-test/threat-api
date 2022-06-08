package main

import (
	"context"
	"fmt"
	"net/http"

	tn "github.com/gdcorp-infosec/threat-api/apis/tanium/taniumLibrary"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	secretID         = "/ThreatTools/Integrations/tanium"
	triageModuleName = "tanium"
)

// TriageModule triage module
type TriageModule struct {
	TaniumClient *http.Client
}

// GetDocs of Tanium triage module
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "Tanium module gets a machine name and returns the programs & versions in real time"}
}

// Supports returns true of we support this ioc type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{triage.GoDaddyHostnameType}
}

// Triage retrieves data by talking to the Tanium library
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {

	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	var span *appsectracing.Span

	span, ctx = tb.TracerLogger.StartSpan(ctx, "Tanium", "triage", "questionquery", "get")
	defer span.End(ctx)

	if m.TaniumClient == nil {
		m.TaniumClient = http.DefaultClient
	}

	var err error
	var triageProgramsData map[string]chan tn.Row
	triageTaniumMachineData := &triage.Data{
		Title:    "Programs and versions installed in the queried machine",
		Metadata: []string{},
	}

	triageProgramsData, err = m.GetProgramsFromGodaddyMachines(ctx, triageRequest)
	if err != nil {
		triageTaniumMachineData.Data = fmt.Sprintf("error from tanium: %s", err)
	} else {
		triageTaniumMachineData.DataType = triage.CSVType
		triageTaniumMachineData.Data, triageTaniumMachineData.Metadata = postProcessing(triageProgramsData)
	}

	return []*triage.Data{triageTaniumMachineData}, nil
}
