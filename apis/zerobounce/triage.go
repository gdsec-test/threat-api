package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gdcorp-infosec/threat-api/apis/zerobounce/zerobounceLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	secretID         = "/ThreatTools/Integrations/zerobounce"
	triageModuleName = "zerobounce"
)

// TriageModule triage module
type TriageModule struct {
	ZeroBounceKey    string
	ZeroBounceClient *http.Client
}

// GetDocs of this module
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "This module validates email addresses"}
}

// Returns true if we support this ioc type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{triage.EmailType}
}

// Triage retrieves data from zerobounce email validation API
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	triageData := &triage.Data{
		Title:    "Email validation data from Zerobounce",
		Metadata: []string{},
	}

	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	secret, err := tb.GetFromCredentialsStore(ctx, secretID, nil)
	if err != nil {
		triageData.Data = fmt.Sprintf("error in retrieving secrets: %s", err)
		return []*triage.Data{triageData}, err
	}

	secretMap := map[string]string{}
	if err := json.Unmarshal([]byte(*secret.SecretString), &secretMap); err != nil {
		triageData.Data = fmt.Sprintf("error in unmarshalling secrets: %s", err)
		return []*triage.Data{triageData}, err
	}

	if m.ZeroBounceClient == nil {
		m.ZeroBounceClient = http.DefaultClient
	}

	m.ZeroBounceKey = secretMap["api_key"]

	var span *appsectracing.Span
	span, ctx = tb.TracerLogger.StartSpan(ctx, "Zerobounce", "zerobounce", "services", "get")
	defer span.End(ctx)

	// Retrieve zerobounce email validation API response
	metaData := zerobounceLibrary.InitializeMetaData(ctx)
	ZeroBounceResults, err := m.GetZeroBounceData(ctx, triageRequest)
	if err != nil {
		triageData.Data = fmt.Sprintf("error from zerobounce: %s", err)
	} else {
		//Dump data as csv
		triageData.DataType = triage.CSVType
		triageData.Data = DumpCSV(ZeroBounceResults, metaData)
		//Calculate and add total number of valid or invalid emails
		triageData.Metadata = zerobounceMetaDataExtract(ZeroBounceResults, metaData)
	}

	return []*triage.Data{triageData}, nil
}
