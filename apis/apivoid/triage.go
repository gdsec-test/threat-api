package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

//TODO: Manage secrets according to the API service
const (
	secretID         = "/ThreatTools/Integrations/APIVoid"
	triageModuleName = "apivoid"
)

// TriageModule triage module TODO: Change struct based on needs from secrets
type TriageModule struct {
	APIVoidKey    string
  APIVoidClient *http.Client
}

// GetDocs of this module TODO: Explain APIVoid service in detail
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "APIVoid module reports many IOCs findings including IP, Domain and URL"} // TODO: Change description
}

// Supports returns true of we support this ioc type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{triage.DomainType, triage.IPType, triage.URLType}
}

// Triage retrieves data from apivoid service TODO: Explain in detail
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	triageAPIVoidData := &triage.Data{
		Title:    "APIvoid data",
		Metadata: []string{},
	}

	// TODO : Extend the triageData to how many ever result type you need

	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	secret, err := tb.GetFromCredentialsStore(ctx, secretID, nil)
	if err != nil {
		triageAPIVoidData.Data = fmt.Sprintf("error in retrieving secrets: %s", err)
		return []*triage.Data{triageAPIVoidData}, err
	}

	if m.APIVoidClient == nil {
		m.APIVoidClient = http.DefaultClient
	}

	m.APIVoidKey = *secret.SecretString

	var span *appsectracing.Span
	// TODO: Assign operationNAme, operationType, operationSubtype, operationAction properly by the naming standards of Elastic APM
	span, ctx = tb.TracerLogger.StartSpan(ctx, "APIVoid", "APIVoid", "services", "get")
	defer span.End(ctx)

	//get the APIVoid data that service offers
	apivoidDataResults, err := m.GetAPIVoidData(ctx, triageRequest)
	if err != nil {
		triageAPIVoidData.Data = fmt.Sprintf("error from apivoid: %s", err)
	} else {
		//Dump data as csv
		triageAPIVoidData.DataType = triage.CSVType
		triageAPIVoidData.Data = dumpCSV(apivoidDataResults, triageRequest.IOCsType)
		//calculate and add the metadata
		triageAPIVoidData.Metadata = apiVoidMetaDataExtract(apivoidDataResults, triageRequest.IOCsType)


	}

	// TODO: Expand the above code block for different IoC's your module is supporting

	return []*triage.Data{triageAPIVoidData}, nil
}
