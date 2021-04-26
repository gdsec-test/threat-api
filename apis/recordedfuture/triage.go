package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	triageModuleName = "recordedfuture"
	secretID         = "/ThreatTools/Integrations/recordedfuture"
)

// TriageModule triage module
type TriageModule struct {
	RFKey    string
	RFClient *http.Client
}

// GetDocs of this module
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "Recorded Future triages CVE, IP"}
}

// Supports returns true of we support this ioc type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{triage.CVEType, triage.IPType}
}

// Triage pulls information from RecordedFuture ConnectAPI
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	triageData := &triage.Data{
		Title:    "Recorded Future Data",
		Metadata: []string{},
	}

	secret, err := tb.GetFromCredentialsStore(ctx, secretID, nil)
	if err != nil {
		triageData.Data = fmt.Sprintf("error in retrieving secrets: %s", err)
		return []*triage.Data{triageData}, err
	}

	m.RFKey = *secret.SecretString
	if m.RFClient == nil {
		m.RFClient = http.DefaultClient
	}

	if triageRequest.IOCsType == triage.CVEType {
		//retrieve results
		rfCVEResults, err := m.cveReportCreate(ctx, triageRequest)
		if err != nil {
			triageData.Data = fmt.Sprintf("error from recorded future API for cve: %s", err)
			return []*triage.Data{triageData}, err
		}

		//calculate and add the metadata
		triageData.Metadata = cveMetaDataExtract(rfCVEResults)

		//Dump data as csv
		triageData.DataType = triage.CSVType
		triageData.Data = dumpCVECSV(rfCVEResults)

	}

	if triageRequest.IOCsType == triage.IPType {
		//retrieve results
		rfIPResults, err := m.ipReportCreate(ctx, triageRequest)
		if err != nil {
			triageData.Data = fmt.Sprintf("error from recorded future API for ip: %s", err)
			return []*triage.Data{triageData}, err
		}

		//calculate and add the metadata
		triageData.Metadata = ipMetaDataExtract(rfIPResults)

		//dump data as csv
		triageData.DataType = triage.CSVType
		triageData.Data = dumpIPCSV(rfIPResults)
	}

	return []*triage.Data{triageData}, nil
}
