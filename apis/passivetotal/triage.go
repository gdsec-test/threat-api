package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
	"net/http"
)

const (
	secretID         = "/ThreatTools/Integrations/passivetotal"
	triageModuleName = "passivetotal"
)

// TriageModule triage module
type TriageModule struct {
	PTKey    string
	PTUser   string
	PTClient *http.Client
}

// GetDocs of this module
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "PassiveTotal data returning PassiveDNS data for past 1 year"}
}

// Supports returns true of we support this ioc type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{triage.DomainType, triage.IPType}
}

// Triage retrieves data from passivetotal
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	triageDataPTData := &triage.Data{
		Title:    "PassiveDNS from Passivetotal",
		Metadata: []string{},
	}
	triageDataPTUniqueData := &triage.Data{
		Title:    "Unique PassiveDNS from Passivetotal",
		Metadata: []string{},
	}

	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	secret, err := tb.GetFromCredentialsStore(ctx, secretID, nil)
	if err != nil {
		triageDataPTData.Data = fmt.Sprintf("error in retrieving secrets: %s", err)
		triageDataPTUniqueData.Data = fmt.Sprintf("error in retrieving secrets: %s", err)
		return []*triage.Data{triageDataPTData, triageDataPTUniqueData}, err
	}

	secretMap := map[string]string{}
	if err := json.Unmarshal([]byte(*secret.SecretString), &secretMap); err != nil {
		triageDataPTData.Data = fmt.Sprintf("error in unmarshaling secrets: %s", err)
		triageDataPTUniqueData.Data = fmt.Sprintf("error in unmarshaling secrets: %s", err)
		return []*triage.Data{triageDataPTData, triageDataPTUniqueData}, err
	}

	if m.PTClient == nil {
		m.PTClient = http.DefaultClient
	}
	m.PTKey = secretMap["key"]
	m.PTUser = secretMap["user"]

	var span *appsectracing.Span
	span, ctx = tb.TracerLogger.StartSpan(ctx, "PassiveTotal", "passivetotal", "services", "get")
	defer span.End(ctx)

	//retrieve PDNS results
	passiveDNSresults, err := m.GetPassiveDNS(ctx, triageRequest)
	if err != nil {
		triageDataPTData.Data = fmt.Sprintf("error from passivetotal: %s", err)
	} else {
		//Dump data as csv
		triageDataPTData.DataType = triage.CSVType
		triageDataPTData.Data = dumpPDNSCSV(passiveDNSresults)
	}

	//retrieve Unique PDNS results
	passiveDNSUniqueresults, err := m.GetUniquePassiveDNS(ctx, triageRequest)
	if err != nil {
		triageDataPTUniqueData.Data = fmt.Sprintf("error from passivetotal: %s", err)
	} else {
		//Dump data as csv
		triageDataPTUniqueData.DataType = triage.CSVType
		triageDataPTUniqueData.Data = dumpUniquePDNSCSV(passiveDNSUniqueresults)
	}

	return []*triage.Data{triageDataPTData, triageDataPTUniqueData}, nil
}
