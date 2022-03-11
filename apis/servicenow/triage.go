package main

import (
	"context"
	"encoding/json"
	"fmt"

	servicenow "github.com/gdcorp-infosec/threat-api/apis/servicenow/servicenowLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	secretID         = "/ThreatTools/Integrations/servicenow"
	triageModuleName = "servicenow"
)

// TriageModule triage module
type TriageModule struct {
	SNClient *servicenow.Client
}

// GetDocs for ServiceNow module
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "ServiceNow module pulls data from Servicenow Tickets and CMDB to enrich GD owned data"}
}

// Supports returns true of we support this ioc type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{triage.GoDaddyHostnameType}
}

// Triage retrieves data from servicenow - CMDB
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	triageCMDBData := &triage.Data{
		Title:    "CMDB ServiceNow data - Assignment and Support Group",
		Metadata: []string{},
	}

	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	secret, err := tb.GetFromCredentialsStore(ctx, secretID, nil)
	if err != nil {
		triageCMDBData.Data = fmt.Sprintf("error in retrieving secrets: %s", err)
		return []*triage.Data{triageCMDBData}, err
	}

	secretMap := map[string]string{}
	if err := json.Unmarshal([]byte(*secret.SecretString), &secretMap); err != nil {
		triageCMDBData.Data = fmt.Sprintf("error in unmarshaling secrets: %s", err)
		return []*triage.Data{triageCMDBData}, err
	}

	// Setting the tableName for CMDB and other credentials to the client
	if m.SNClient == nil {
		m.SNClient, err = servicenow.New(secretMap["url"], secretMap["username"], secretMap["password"], "cmdb_ci")
		if err != nil {
			triageCMDBData.Data = fmt.Sprintf("error in creating the clients: %s", err)
			return []*triage.Data{triageCMDBData}, err
		}
	}

	var span *appsectracing.Span
	span, ctx = tb.TracerLogger.StartSpan(ctx, "ServiceNow", "servicenow", "cmdb", "get")
	defer span.End(ctx)

	if triageRequest.IOCsType == triage.GoDaddyHostnameType {
		//get the example data that service offers
		cmdbDataResults, err := m.GetCMDBData(ctx, triageRequest.IOCs)
		if err != nil {
			span.LogKV("Error", err)
			triageCMDBData.Data = fmt.Sprintf("error from passivetotal: %s", err)
		} else {
			//Dump data as csv
			triageCMDBData.DataType = triage.CSVType
			triageCMDBData.Data = dumpCSV(cmdbDataResults)
		}
	}

	return []*triage.Data{triageCMDBData}, nil
}
