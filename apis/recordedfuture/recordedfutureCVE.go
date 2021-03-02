package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
	"strings"
	"sync"
)

//cveReportCreate generates a map of CVEReport from RF API
func (m *TriageModule) cveReportCreate(ctx context.Context, triageRequest *triage.Request) (map[string]*CVEReport, error) {
	rfCVEResults := make(map[string]*CVEReport)

	//TODO: Check on threadLimit
	wg := sync.WaitGroup{}
	wg.Add(len(triageRequest.IOCs))
	rfCVEResultsLock := sync.Mutex{}

	for _, cve := range triageRequest.IOCs {
		select {
		case <-ctx.Done():
			break
		default:
		}

		go func(cve string) {
			defer wg.Done()
			// Calling RF API with metadata switched off
			rfCVEResult, err := m.EnrichCVE(ctx, cve, CVEReportFields, false)
			if err != nil {
				rfCVEResultsLock.Lock()
				rfCVEResults[cve] = nil
				rfCVEResultsLock.Unlock()
				return
			}

			rfCVEResultsLock.Lock()
			rfCVEResults[cve] = rfCVEResult
			rfCVEResultsLock.Unlock()
		}(cve)
	}

	wg.Wait()
	return rfCVEResults, nil
}

//cveMetaDataExtract gets the high level insights for CVE
func cveMetaDataExtract(rfCVEResults map[string]*CVEReport) []string {
	var triageMetaData, accessVectors []string
	riskCVE := 0
	affectedSystemsCPE := 0

	for cve, data := range rfCVEResults {
		// Add the RF Intelligence Card link to every CVE for easy access to people with access
		if data.Data.IntelCard != "" {
			triageMetaData = append(triageMetaData, fmt.Sprintf("RF Link for %s: %s", cve, data.Data.IntelCard))
		}

		// Calculate on risk score
		if data.Data.Risk.Score > 60 {
			riskCVE += 1
		}

		// keep count on the affected systems with the CPE's associated
		affectedSystemsCPE += len(data.Data.Cpe)

		// collect all the access vectors for the CVE's
		accessVectors = append(accessVectors, data.Data.Cvss.AccessVector)
	}

	if riskCVE > 0 {
		triageMetaData = append(triageMetaData, fmt.Sprintf("%d CVE's have a risk score > 60", riskCVE))
	}
	if affectedSystemsCPE > 0 {
		triageMetaData = append(triageMetaData, fmt.Sprintf("CPE's associated with list of CVE's : %d", affectedSystemsCPE))
	}
	if len(accessVectors) > 0 {
		triageMetaData = append(triageMetaData, fmt.Sprintf("Access Vectors for CVE's : %s", strings.Join(accessVectors, ",")))
	}
	return triageMetaData
}

//dumpCVECSV dumps the triage data to CSV
func dumpCVECSV(rfCVEResults map[string]*CVEReport) string {
	//Dump data as csv
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	csv.Write([]string{
		"IntelCardLink",
		"Risk Score",
		"Criticality",
		"CriticalityLabel",
		// TODO: Evidence Details- show it in a better way
		"CommonNames",
		"First Seen",
		"Last Seen",
		"ThreatLists",
		"Affected Machines: CPE",
		"RawRisk Rules Associated",
		"Access Vector",
		"Auth Required",
		"Access Complexity",
		"Confidentiality",
		"Integrity",
		"NVD Description",
		//TODO: "Analyst Notes- a better way to display",
	})
	for _, data := range rfCVEResults {
		// Processing few non string data before adding to CSV
		var threatLists, rawriskRules []string
		for _, threatlist := range data.Data.ThreatLists {
			//TODO: Check on threatlist is a defined struct with other edge cases
			threatLists = append(threatLists, threatlist.(string))
		}
		for _, rawrisk := range data.Data.Rawrisk {
			rawriskRules = append(rawriskRules, rawrisk.Rule)
		}

		cols := []string{
			data.Data.IntelCard,
			fmt.Sprintf("%d", data.Data.Risk.Score),
			fmt.Sprintf("%d", data.Data.Risk.Criticality),
			data.Data.Risk.CriticalityLabel,
			strings.Join(data.Data.CommonNames, " "),
			data.Data.Timestamps.FirstSeen.String(),
			data.Data.Timestamps.LastSeen.String(),
			strings.Join(threatLists, " "),
			strings.Join(data.Data.Cpe, " "),
			strings.Join(rawriskRules, " "),
			data.Data.Cvss.AccessVector,
			data.Data.Cvss.Authentication,
			data.Data.Cvss.AccessComplexity,
			data.Data.Cvss.Confidentiality,
			data.Data.Cvss.Integrity,
			data.Data.NvdDescription,
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}
