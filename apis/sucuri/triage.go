package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	triageModuleName = "sucuri"
)

// TriageModule triage module
type TriageModule struct {
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

	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)


	if m.SucuriClient == nil {
		m.SucuriClient = http.DefaultClient
	}


	var span *appsectracing.Span
	span, ctx = tb.TracerLogger.StartSpan(ctx, "Sucuri", "sucuri", "services", "get")
	defer span.End(ctx)

	//Get the example data that service offers
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
