package main

import (
	"context"
	"fmt"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
	"net/http"
)

//tb Toolbox to use secrets manager
var tb *toolbox.Toolbox

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
	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	secret, err := tb.GetFromCredentialsStore(ctx, secretID, nil)
	if err != nil {
		triageData.Data = fmt.Sprintf("error in retrieving secrets: %s", err)
		return []*triage.Data{triageData}, err
	}

	m.RFKey = *secret.SecretString
	if m.RFClient == nil {
		m.RFClient = http.DefaultClient
	}

	//TODO: TAKE OUT
	fmt.Printf("Retrieved password from secrets manager %d \n", len(m.RFKey))
	triageData.Metadata = append(triageData.Metadata, fmt.Sprintf("Retrieved password from secrets manager %d", len(m.RFKey)))

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
		//TODO: TAKE OUT
		fmt.Printf("its an IP Type request\n")
		triageData.Metadata = append(triageData.Metadata, fmt.Sprintf("its an IP Type request"))

		//retrieve results
		rfIPResults, err := m.ipReportCreate(ctx, triageRequest)
		if err != nil {
			triageData.Data = fmt.Sprintf("error from recorded future API for ip: %s", err)
			return []*triage.Data{triageData}, err
		}

		//TODO: TAKE OUT
		fmt.Printf("I got data back without errors %d \n", len(rfIPResults))
		triageData.Metadata = append(triageData.Metadata, fmt.Sprintf("I got data back without errors %d", len(rfIPResults)))

		//calculate and add the metadata
		//TODO: TAKE OUT
		for _, text := range ipMetaDataExtract(rfIPResults) {
			fmt.Printf("%s \n", text)
			triageData.Metadata = append(triageData.Metadata, text)
		}
		//triageData.Metadata = ipMetaDataExtract(rfIPResults)

		//dump data as csv
		triageData.DataType = triage.CSVType
		triageData.Data = dumpIPCSV(rfIPResults)
	}

	return []*triage.Data{triageData}, nil
}
