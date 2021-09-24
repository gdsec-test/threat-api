package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

// TriageModule triage module
type TriageModule struct {
	NVDClient *http.Client
}

const (
	triageModuleName = "nvd"
)

// GetDocs of this module
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "CVE data from NVD"}
}

// Supports returns true of we support this ioc type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{triage.CVEType}
}

// Triage retrieves data from nvd service
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	triageNVDData := &triage.Data{
		Title:    "CVE Data from NVD",
		Metadata: []string{},
	}

	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	if m.NVDClient == nil {
		m.NVDClient = http.DefaultClient
	}

	var span *appsectracing.Span
	span, ctx = tb.TracerLogger.StartSpan(ctx, "NVD", "nvd", "services", "get")
	defer span.End(ctx)

	//retrieve NVD results
	NVDResults, err := m.GetNVDData(ctx, triageRequest)
	if err != nil {
		triageNVDData.Data = fmt.Sprintf("error from NVD: %s", err)
	} else {
		//Dump data as csv
		triageNVDData.DataType = triage.CSVType
		//calculate and add the metadata
		triageNVDData.Metadata = cveMetaDataExtract(NVDResults)
		triageNVDData.Data = dumpCSV(NVDResults)
	}

	return []*triage.Data{triageNVDData}, nil
}
