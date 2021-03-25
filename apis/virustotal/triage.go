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
	secretID = "/ThreatTools/Integrations/virustotal"
)

// Triage module
type TriageModule struct {
}

// GetDocs of this module
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "Return information about scanned filed and URLs from VirusTotal."}
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

// Triage finds malware domains according to URLhaus by ASN
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	triageData := &triage.Data{
		Title:    "URLhaus",
		Metadata: []string{},
	}

	switch triageRequest.IOCsType {
	case triage.MD5Type, triage.SHA256Type:
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
	case triage.DomainType:
	case triage.IPType:
	case triage.URLType:
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
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}
