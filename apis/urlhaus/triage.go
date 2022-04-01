package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"

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
	return &triage.Doc{Name: triageModuleName, Description: "Find hosted malware from urlhaus based on hash, domain, or URL."}
}

// Supports returns true of we support this IoC type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{
		triage.DomainType,
		triage.IPType,
		triage.URLType,
		triage.MD5Type,
		triage.SHA256Type,
	}
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
	case triage.MD5Type:
		triageData.Title = "Malicious URLs hosting this MD5 hash (URLhaus)"
		entries := make([]*UrlhausPayloadEntry, len(triageRequest.IOCs))
		for i, ioc := range triageRequest.IOCs {
			entry, err := GetMd5(ctx, ioc)
			if err != nil {
				fmt.Println(err)
				continue
			}
			entries[i] = entry
		}
		triageData.Data = HashesToCsv(entries)
	case triage.SHA256Type:
		triageData.Title = "Malicious URLs hosting this SHA256 hash (URLhaus)"
		entries := make([]*UrlhausPayloadEntry, len(triageRequest.IOCs))
		for i, ioc := range triageRequest.IOCs {
			entry, err := GetSha256(ctx, ioc)
			if err != nil {
				fmt.Println(err)
				continue
			}
			entries[i] = entry
		}
		triageData.Data = HashesToCsv(entries)
	case triage.DomainType, triage.IPType:
		triageData.Title = "Information about this host (URLhaus)"
		entries := make([]*UrlhausHostEntry, len(triageRequest.IOCs))
		for i, ioc := range triageRequest.IOCs {
			entry, err := GetDomainOrIp(ctx, ioc)
			if err != nil {
				fmt.Println(err)
				continue
			}
			entries[i] = entry
		}
		triageData.Data = HostsToCsv(entries)
	case triage.URLType:
		triageData.Title = "Information about this URL address (URLhaus)"
		entries := make([]*UrlhausUrlEntry, len(triageRequest.IOCs))
		for i, ioc := range triageRequest.IOCs {
			entry, err := GetUrl(ctx, ioc)
			if err != nil {
				fmt.Println(err)
				continue
			}
			entries[i] = entry
		}
		triageData.Data = UrlsToCsv(entries)
	}

	return []*triage.Data{triageData}, nil
}

func HostsToCsv(hosts []*UrlhausHostEntry) string {
	// Dump data into CSV format
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Headers
	csv.Write([]string{
		"First Seen",
		"URL Summary",
		"Spamhaus",
		"SURBL",
		"Badness",
	})
	// Rows
	for _, host := range hosts {
		if host == nil {
			continue
		}
		cols := []string{
			host.First,
			fmt.Sprintf("Seen at %d different URLs", host.Count),
			host.Blacklists.SpamhausStatus,
			host.Blacklists.SurblStatus,
			fmt.Sprintf("%0.2f", host.GetBadnessScore()),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}

func UrlsToCsv(urls []*UrlhausUrlEntry) string {
	// Dump data into CSV format
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Headers
	csv.Write([]string{
		"Host",
		"Status",
		"Added",
		"Taken Down",
		"Badness",
	})
	// Rows
	for _, url := range urls {
		if url == nil {
			continue
		}
		cols := []string{
			url.Host,
			url.Status,
			url.Added,
			fmt.Sprint(url.Takedown),
			fmt.Sprintf("%0.2f", url.GetBadnessScore()),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}

func HashesToCsv(payloads []*UrlhausPayloadEntry) string {
	// Dump data into CSV format
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Headers
	csv.Write([]string{
		"MD5",
		"SHA256",
		"File Type",
		"File Size",
		"First Seen",
		"URL Summary",
		"Badness",
	})
	// Rows
	for _, payload := range payloads {
		if payload == nil {
			continue
		}
		cols := []string{
			payload.Md5,
			payload.Sha,
			payload.FileType,
			fmt.Sprint(payload.Size),
			payload.First,
			fmt.Sprintf("Seen at %d different URLs", payload.UrlCount),
			fmt.Sprintf("%0.2f", payload.GetBadnessScore()),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}
