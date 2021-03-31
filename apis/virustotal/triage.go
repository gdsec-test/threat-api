package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"time"

	vt "github.com/VirusTotal/vt-go"
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
		Title:    "VirusTotal",
		Metadata: []string{},
	}

	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	secret, err := tb.GetFromCredentialsStore(ctx, secretID, nil)
	if err != nil {
		triageData.Data = fmt.Sprintf("Error retrieving secret with key, %s: %s", secretID, err)
		return []*triage.Data{triageData}, err
	}
	apiKey := *secret.SecretString
	virusTotal * VirusTotal = NewVirusTotal(apiKey)

	switch triageRequest.IOCsType {
	case triage.MD5Type, triage.SHA256Type:
		triageData.Title = "Analyses of previously seen hashes"
		entries := make([]*vt.Object, len(triageRequest.IOCs))
		for i, ioc := range triageRequest.IOCs {
			entry, err := virusTotal.GetHash(ioc)
			if err != nil {
				fmt.Println(err)
				continue
			}
			entries[i] = entry
		}
		triageData.Data = HashesToCsv(entries)
	case triage.DomainType:
		triageData.Title = "Analyses of previously seen domain names"
		entries := make([]*vt.Object, len(triageRequest.IOCs))
		for i, ioc := range triageRequest.IOCs {
			entry, err := virusTotal.GetDomain(ioc)
			if err != nil {
				fmt.Println(err)
				continue
			}
			entries[i] = entry
		}
		triageData.Data = DomainsToCsv(entries)
	case triage.IPType:
		triageData.Title = "Analyses of previously seen IP addresses"
		entries := make([]*vt.Object, len(triageRequest.IOCs))
		for i, ioc := range triageRequest.IOCs {
			entry, err := virusTotal.GetAddress(ioc)
			if err != nil {
				fmt.Println(err)
				continue
			}
			entries[i] = entry
		}
		triageData.Data = IpsToCsv(entries)
	case triage.URLType:
		triageData.Title = "Analyses of previously seen URLs"
		entries := make([]*vt.Object, len(triageRequest.IOCs))
		for i, ioc := range triageRequest.IOCs {
			entry, err := virusTotal.GetUrl(ioc)
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

func HashesToCsv(payloads []*vt.Object) string {
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)

	// convert the "first seen in the wild" field from
	// the Linux epoch time as an integer into a RFC 3339 string
	t := time.Unix(payload.GetInt64("first_seen_itw_date", 0))
	firstSeen := t.Format(time.RFC3339)

	csv.Write([]string{
		"MD5",
		"SHA1",
		"SHA256",
		"Magic",
		"File Size",
		"First Seen",
		"Reputation",
	})

	for _, payload := range payloads {
		if payload == nil {
			continue
		}
		cols := []string{
			payload.GetString("md5"),
			payload.GetString("sha1"),
			payload.GetString("sha256"),
			payload.GetString("magic"),
			str(payload.GetInt64("size")),
			firstSeen,
			str(payload.GetInt64("reputation"))
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}

func DomainsToCsv(payloads []*vt.Object) string {
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)

	// convert the creation date field from
	// the Linux epoch time as an integer into a RFC 3339 string
	t := time.Unix(payload.GetInt64("creation_date", 0))
	creationDate := t.Format(time.RFC3339)

	csv.Write([]string{
		"Created",
		"Reputation",
		"WHOIS",
	})

	for _, payload := range payloads {
		if payload == nil {
			continue
		}
		cols := []string{
			creationDate,
			str(payload.GetInt64("reputation"))
			payload.GetString("whois"),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}

func IpsToCsv(payloads []*vt.Object) string {
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)

	csv.Write([]string{
		"Owner",
		"ASN",
		"Country",
	})

	for _, payload := range payloads {
		if payload == nil {
			continue
		}
		cols := []string{
			payload.GetString("as_owner"),
			str(payload.GetInt64("asn")),
			payload.GetString("country"),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}

func UrlsToCsv(payloads []*vt.Object) string {
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)

	// convert the first submission date field from
	// the Linux epoch time as an integer into a RFC 3339 string
	t := time.Unix(payload.GetInt64("first_submission_date", 0))
	firstSubmission := t.Format(time.RFC3339)

	csv.Write([]string{
		"URL",
		"Title",
		"Reputation",
		"First Submission",
		"Analysis",
	})

	for _, payload := range payloads {
		if payload == nil {
			continue
		}
		cols := []string{
			payload.GetString("url"),
			payload.GetString("title"),
			payload.GetInt64("reputation"),
			firstSubmission,
			payload.GetString("last_analysis_results.category"),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}
