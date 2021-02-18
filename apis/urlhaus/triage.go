package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

// TriageModule triage module
type TriageModule struct {
}

// GetDocs of this module
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "Download records of threats by ASNs"}
}

// Supports returns true of we support this ioc type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{triage.UnknownType}
}

// Triage Finds whois information from a list of domains
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	entries := FetchSingleAsn(ctx, asns)

	triageData := &triage.Data{
		Title:    "URLhaus threat-ASN downloader",
		Metadata: []string{},
	}

	result, err := json.Marshal(entries)
	if err != nil {
		triageData.Data = fmt.Sprintf("Error marshaling: %s", err)
		return []*triage.Data{triageData}, nil
	}
	triageData.Data = string(result)
	triageData.DataType = triage.JSONType
	return []*triage.Data{triageData}, nil
}
