package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	paramUrlhausAsns = "URLhaus-ASNs"
)

// Triage module
type TriageModule struct {
}

// GetDocs of this module
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "Download records of threats by ASNs"}
}

// Supports returns true of we support this IoC type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{triage.UnknownType}
}

func (m *TriageModule) GetAsns(ctx context.Context) (string, error) {
	t := toolbox.GetToolbox()
	defer t.Close(ctx)

	parameter, err := t.GetFromParameterStore(context.Background(), paramUrlhausAsns, false)
	if err != nil {
		return "", err
	}
	return *parameter.Value, nil
}

// Triage finds malware domains according to URLhaus by ASN
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	triageData := &triage.Data{
		Title:    "URLhaus threat-ASN downloader",
		Metadata: []string{},
	}

	// asns is a comma separated string
	asnsJoined, err := m.GetAsns(ctx)
	if err != nil {
		triageData.Data = fmt.Sprintf("Error retrieving the ASNs from Parameter Store: %s", err)
		return []*triage.Data{triageData}, nil
	}
	asns := strings.Split(asnsJoined, ",")
	entries := DownloadAsns(ctx, asns)

	result, err := json.Marshal(entries)
	if err != nil {
		triageData.Data = fmt.Sprintf("Error marshaling: %s", err)
		return []*triage.Data{triageData}, nil
	}
	triageData.Data = string(result)
	triageData.DataType = triage.JSONType
	return []*triage.Data{triageData}, nil
}
