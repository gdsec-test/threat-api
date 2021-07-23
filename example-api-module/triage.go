package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	secretID         = "/ThreatTools/Integrations/example"
	triageModuleName = "example"
)

// TriageModule triage module
type TriageModule struct {
	ExampleKey  string
	ExampleUser string
	PTClient    *http.Client
}

// GetDocs of this module TODO: Example in detail
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "What your example module does"}
}

// Supports returns true of we support this ioc type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{} // TODO:Add the supported IoC modules
}

// Triage retrieves data from example service
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	triageDataPTData := &triage.Data{
		Title:    "Data from Example",
		Metadata: []string{},
	}

	// TODO : Extend the triageData to how many ever result type you need

	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	secret, err := tb.GetFromCredentialsStore(ctx, secretID, nil)
	if err != nil {
		triageDataPTData.Data = fmt.Sprintf("error in retrieving secrets: %s", err)
		return []*triage.Data{triageDataPTData}, err
	}

	secretMap := map[string]string{}
	if err := json.Unmarshal([]byte(*secret.SecretString), &secretMap); err != nil {
		triageDataPTData.Data = fmt.Sprintf("error in unmarshaling secrets: %s", err)
		return []*triage.Data{triageDataPTData}, err
	}

	if m.PTClient == nil {
		m.PTClient = http.DefaultClient
	}

	// TODO: If you have 2 secrets in the secrets manager. Else directly assign the returned secret as the API key
	m.ExampleKey = secretMap["key"]
	m.ExampleUser = secretMap["user"]

	var span *appsectracing.Span
	// TODO: Assign operationNAme, operationType, operationSubtype, operationAction properly by the naming standards of Elastic APM
	span, ctx = tb.TracerLogger.StartSpan(ctx, "Example", "example", "services", "get")
	defer span.End(ctx)

	//get the example data that service offers
	egDataResults, err := m.GetExampleData(ctx, triageRequest)
	if err != nil {
		triageDataPTData.Data = fmt.Sprintf("error from passivetotal: %s", err)
	} else {
		//Dump data as csv
		triageDataPTData.DataType = triage.CSVType
		triageDataPTData.Data = dumpCSV(egDataResults)
	}

	// TODO: Expand the above code block for different IoC's your module is supporting

	return []*triage.Data{triageDataPTData}, nil
}
