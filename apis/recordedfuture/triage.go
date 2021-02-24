package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

// TriageModule triage module
type TriageModule struct {
}

// GetDocs of this module
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "Recorded Future triages CVE currently"}
}

// Supports returns true of we support this ioc type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{triage.CVEType}
}

// Triage Finds the CVE information from RF
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {

	if triageRequest.IOCsType == triage.CVEType {
		rfCVEResults, err := EnrichCVE(ctx, triageRequest.IOCs)
	}

	triageData := &triage.Data{
		Title:    "Recorded Future Data",
		Metadata: []string{},
	}

	// Add some metadata if we found something interesting in the whois stats
	// Dump full data if we are doing full dump
	if triageRequest.Verbose {
		result, err := json.Marshal(rfCVEResults)
		if err != nil {
			triageData.Data = fmt.Sprintf("Error marshaling: %s", err)
			return []*triage.Data{triageData}, nil
		}
		triageData.Data = string(result)
		triageData.DataType = triage.JSONType
		return []*triage.Data{triageData}, nil
	}

	triageData.Data = dumpCSV(shodanhosts)
	return []*triage.Data{triageData}, nil
}

func dumpCSV(shodanhosts []*Host) string {
	//Dump data as csv
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	csv.Write([]string{
		"Domain",
		"IP",
		"ASN",
		"City",
		"Country",
		"ISP",
		"OS",
		"Hostnames",
		"Vulnerabilities",
		"LastUpdate",
		"Ports",
	})
	for _, host := range shodanhosts {
		cols := []string{
			host.Domain,
			host.ShodanHost.IP.String(),
			host.ShodanHost.ASN,
			host.ShodanHost.City,
			host.ShodanHost.Country,
			host.ShodanHost.ISP,
			host.ShodanHost.OS,
			strings.Join(host.ShodanHost.Hostnames, " "),
			strings.Join(host.ShodanHost.Vulnerabilities, " "),
			host.ShodanHost.LastUpdate,
			strings.Trim(strings.Join(strings.Split(fmt.Sprint(host.ShodanHost.Ports), " "), " "), "[]"),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}
