package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

//"github.com/vertoforce/gourlhaus"

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
		Title:    "URLhaus",
		Metadata: []string{},
	}

	switch triageRequest.IOCsType {
	case triage.DomainType, triage.IPType:
		fmt.Print("")
		/*
			case triage.MD5Type, triage.SHA256Type:
				triageData.Title = "Malicious URLs hosting this hash (URLhaus)"
				entries, err = urlHausDatabase.FindEntriesHostingHashes(ctx, triageRequest.IOCs, triageRequest.IOCsType, api)
				if err != nil {
					triageData.Data = fmt.Sprintf("Error finding entries hosting hashes in urlhaus: %s", err)
					return []*triage.Data{triageData}, nil
				}
				if len(entries) > 0 {
					triageData.Metadata = append(triageData.Metadata, fmt.Sprintf("%d malicious urls have hosted these hashes at some point", len(entries)))
				}
			case triage.DomainType, triage.IPType:
				triageData.Title = "Malicious URLs at this domain/IP (URLhaus)"
				entries, err = urlHausDatabase.FindEntriesWithDomainOrIP(ctx, triageRequest.IOCs, api)
				if err != nil {
					triageData.Data = fmt.Sprintf("Error finding entries with domain or ip in urlhaus: %s", err)
					return []*triage.Data{triageData}, nil
				}
				if len(entries) > 0 {
					triageData.Metadata = append(triageData.Metadata, fmt.Sprintf("%d malicious urls have been hosted on this domain at some point", len(entries)))
				}
			case triage.URLType:
				triageData.Title = "URLs that are malicious (found in URLhaus)"
				entries, err = urlHausDatabase.FindEntriesWithURL(ctx, triageRequest.IOCs, api)
				if err != nil {
					triageData.Data = fmt.Sprintf("Error finding entries with url in urlhaus: %s", err)
					return []*triage.Data{triageData}, nil
				}
				if len(entries) > 0 {
					triageData.Metadata = append(triageData.Metadata, fmt.Sprintf("%d/%d of these urls are malicious (found on URLhaus)", len(entries), len(triageRequest.IOCs)))
				}
		*/
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
