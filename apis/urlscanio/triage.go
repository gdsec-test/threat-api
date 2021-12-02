package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gdcorp-infosec/threat-api/apis/urlscanio/urlscanioLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	secretID         = "/ThreatTools/Integrations/urlscanio"
	triageModuleName = "urlscanio"
)

type TriageModule struct {
	urlscanKey    string
	urlscanClient *http.Client
}

// This module submits URLs to urlscan.io and retrieves available safety information
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "This module retrieves URL safety information from urlscan.io"}
}

// Returns true if we support this ioc type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{triage.URLType}
}

// Triage retrieves data from urlscan.io
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	triageData := &triage.Data{
		Title:    "URL scan data from urlscan.io",
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
		triageData.Data = fmt.Sprintf("error in unmarshaling secrets: %s", err)
		return []*triage.Data{triageData}, err
	}

	if m.urlscanClient == nil {
		m.urlscanClient = http.DefaultClient
	}

	m.urlscanKey = secretMap["key"]

	var span *appsectracing.Span
	// Log spans in Elastic APM
	span, ctx = tb.TracerLogger.StartSpan(ctx, "URLScan", "urlscan", "services", "get")
	defer span.End(ctx)

	// Retrieve URL scan results
	metaDataHolder := urlscanioLibrary.InitializeMetaData(ctx)
	urlSubmissionResult, err := m.GetURLScanData(ctx, triageRequest, metaDataHolder)
	if err != nil && urlSubmissionResult != nil {
		triageData.Data = fmt.Sprintf("error from urlscan: %s", err)
	} else {
		//Dump data as csv
		triageData.DataType = triage.CSVType
		triageData.Data = dumpCSV(urlSubmissionResult, metaDataHolder)
		triageData.Metadata = urlscanMetaDataExtract(metaDataHolder)
	}

	return []*triage.Data{triageData}, nil
}
