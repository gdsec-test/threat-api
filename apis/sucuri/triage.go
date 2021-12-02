package main

import (
	"context"
	//"encoding/json"
	"fmt"
	"net/http"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

//TODO: Manage secrets according to the API service
const (
	//secretID         = "/ThreatTools/Integrations/sucuri"
	triageModuleName = "sucuri"
)

// TriageModule triage module TODO: Change struct based on needs from secrets
type TriageModule struct {
	//ExampleKey  string
	//ExampleUser string
	SucuriClient *http.Client
}

// GetDocs of this module
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "Data from Sucuri"}
}

// Supports returns true of we support this ioc type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{triage.DomainType} // TODO:Add the supported IoC modules
}

// Triage retrieves data from sucuri service TODO: Explain in detail
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	triageSucuriData := &triage.Data{
		Title:    "Data from sucuri",
		Metadata: []string{},
	}

	// TODO : Extend the triageData to how many ever result type you need

	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	/* 	secret, err := tb.GetFromCredentialsStore(ctx, secretID, nil)
	if err != nil {
		triageExampleData.Data = fmt.Sprintf("error in retrieving secrets: %s", err)
		return []*triage.Data{triageExampleData}, err
	}

	secretMap := map[string]string{}
	if err := json.Unmarshal([]byte(*secret.SecretString), &secretMap); err != nil {
		triageExampleData.Data = fmt.Sprintf("error in unmarshaling secrets: %s", err)
		return []*triage.Data{triageExampleData}, err
	} */

	if m.SucuriClient == nil {
		m.SucuriClient = http.DefaultClient
	}

	// TODO: If you have 2 secrets in the secrets manager. Else directly assign the returned secret as the API key
	/* 	m.ExampleKey = secretMap["key"]
	m.ExampleUser = secretMap["user"] */

	var span *appsectracing.Span
	span, ctx = tb.TracerLogger.StartSpan(ctx, "Sucuri", "sucuri", "services", "get")
	defer span.End(ctx)

	//get the example data that service offers
	SucuriResults, err := m.GetSucuriData(ctx, triageRequest)
	if err != nil {
		triageSucuriData.Data = fmt.Sprintf("error from Sucuri: %s", err)
	} else {
		//Dump data as csv
		triageSucuriData.DataType = triage.CSVType
		triageSucuriData.Data = dumpCSV(SucuriResults)
	}


	return []*triage.Data{triageSucuriData}, nil
}
