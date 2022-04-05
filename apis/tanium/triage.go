package main

import (
	"context"
	"fmt"
	tn "github.com/gdcorp-infosec/threat-api/apis/tanium/taniumLibrary"
	"net/http"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	secretID         = "/ThreatTools/Integrations/tanium"
	triageModuleName = "tanium"
)

// TriageModule triage module TODO: Change struct after auth
type TriageModule struct {
	ExampleKey    string
	ExampleUser   string
	ExampleClient *http.Client
}

// GetDocs of Tanium triage module
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "Tanium module gets a machine name and returns the programs & versions in real time"}
}

// Supports returns true of we support this ioc type
func (m *TriageModule) Supports() []triage.IOCType {
	//TODO: uncomment to get actual results after Auth
	//return []triage.IOCType{triage.*********}
	return nil
}

// Triage retrieves data by talking to the Tanium library
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {

	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	// TODO: Handle secrets after Auth, and have a Tanium initClient here
	//secret, err := tb.GetFromCredentialsStore(ctx, secretID, nil)
	//if err != nil {
	//	triageExampleData.Data = fmt.Sprintf("error in retrieving secrets: %s", err)
	//	return []*triage.Data{triageExampleData}, err
	//}
	//
	//secretMap := map[string]string{}
	//if err := json.Unmarshal([]byte(*secret.SecretString), &secretMap); err != nil {
	//	triageExampleData.Data = fmt.Sprintf("error in unmarshaling secrets: %s", err)
	//	return []*triage.Data{triageExampleData}, err
	//}
	//
	//if m.ExampleClient == nil {
	//	m.ExampleClient = http.DefaultClient
	//}
	//
	//m.ExampleKey = secretMap["key"]
	//m.ExampleUser = secretMap["user"]

	var span *appsectracing.Span

	span, ctx = tb.TracerLogger.StartSpan(ctx, "Tanium", "triage", "questionquery", "get")
	defer span.End(ctx)

	var err error
	var triageProgramsData map[string]chan tn.Row
	triageTaniumMachineData := &triage.Data{
		Title:    "Programs and versions installed in the queried machine",
		Metadata: []string{},
	}

	switch triageRequest.IOCsType {
	case triage.CPEType:
		//triageDatas = m.triageCPEs(ctx, triageRequest)
	case triage.CVEType:
		//triageDatas = m.triageCVEs(ctx, triageRequest)
	case triage.GoDaddyHostnameType:
		triageProgramsData, err = m.GetProgramsFromGodaddyMachines(ctx, triageRequest)
	}

	if err != nil {
		triageTaniumMachineData.Data = fmt.Sprintf("error from tanium: %s", err)
	} else {
		triageTaniumMachineData.DataType = triage.CSVType
		triageTaniumMachineData.Data = dumpCSV(triageProgramsData)
	}

	return []*triage.Data{triageTaniumMachineData}, nil
}
