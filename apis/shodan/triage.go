package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
	"github.com/ns3777k/go-shodan/v4/shodan"
	"github.com/opentracing/opentracing-go"
)

var tb *toolbox.Toolbox

const (
	secretID     = "/ThreatTools/Integrations/shodan"
	versionStage = "AWSCURRENT"
)

// TriageModule triage module
type TriageModule struct {
	ShodanKey    string
	shodanClient *shodan.Client
}

// GetDocs of this module
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "Shodan data on vulnerabilities and ports"}
}

// Supports returns true of we support this ioc type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{triage.DomainType, triage.IPType}
}

// Triage Finds shodan data for domains and ips
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	triageData := &triage.Data{
		Title:    "Shodan results",
		Metadata: []string{},
	}

	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	secret, err := tb.GetFromCredentialsStore(ctx, secretID, versionStage)
	if err != nil {
		triageData.Data = fmt.Sprintf("error in retrieving secrets: %s", err)
		return []*triage.Data{triageData}, err
	}
	m.ShodanKey = *secret.SecretString
	if m.shodanClient == nil {
		m.shodanClient = shodan.NewClient(nil, m.ShodanKey)
	}

	// Map of domain name to IP (if we are working with domains (not ips), we should track the domain name for the output)
	ips := map[string]*net.IP{}
	if triageRequest.IOCsType == triage.DomainType {
		ips = m.resolveDomains(ctx, triageRequest.IOCs)
	} else if triageRequest.IOCsType == triage.IPType {
		for _, ip := range triageRequest.IOCs {
			ipParsed := net.ParseIP(ip)
			if ipParsed != nil {
				ips[ip] = &ipParsed
			}
		}
	}

	var span opentracing.Span
	span, ctx = opentracing.StartSpanFromContext(ctx, "ShodanGetServices")
	defer span.Finish()

	shodanhosts := m.GetServicesForIPs(ctx, ips)
	if len(shodanhosts) == 0 {
		return []*triage.Data{triageData}, nil
	}
	vulnerabilities := 0
	vulnerableIPs := 0
	geolocationMap := map[string]struct{}{}

	for _, host := range shodanhosts {
		if len(host.ShodanHost.Vulnerabilities) > 0 {
			vulnerableIPs += 1
		}
		vulnerabilities += len(host.ShodanHost.Vulnerabilities)
		geolocationMap[host.ShodanHost.Country] = struct{}{}

	}
	if vulnerableIPs > 0 {
		triageData.Metadata = append(triageData.Metadata, fmt.Sprintf("%d/%d %s's have vulnerabilities associated", vulnerableIPs, len(triageRequest.IOCs), triageRequest.IOCsType))
	}
	if vulnerabilities > 0 {
		triageData.Metadata = append(triageData.Metadata, fmt.Sprintf("There are %d vulnerabilities on these %ss", vulnerabilities, triageRequest.IOCsType))
	}

	var geolocations []string
	for key := range geolocationMap {
		geolocations = append(geolocations, key)
	}

	sort.Strings(geolocations)

	triageData.Metadata = append(triageData.Metadata, fmt.Sprintf("These %ss are located in: %s", triageRequest.IOCsType, strings.Join(geolocations, ", ")))

	// Dump full data if we are doing full dump
	if triageRequest.Verbose {
		result, err := json.Marshal(shodanhosts)
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
