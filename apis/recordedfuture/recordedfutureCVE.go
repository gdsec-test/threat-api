package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"strings"
	"sync"

	rf "github.com/gdcorp-infosec/threat-api/apis/recordedfuture/recordedfutureLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	maxThreadCount = 5
)

//cveReportCreate generates a map of CVEReport from RF API
func (m *TriageModule) cveReportCreate(ctx context.Context, triageRequest *triage.Request) (map[string]*rf.CVEReport, error) {
	rfCVEResults := make(map[string]*rf.CVEReport)

	wg := sync.WaitGroup{}
	rfCVEResultsLock := sync.Mutex{}
	threadLimit := make(chan int, maxThreadCount)

	for _, cve := range triageRequest.IOCs {
		select {
		case <-ctx.Done():
			break
		case threadLimit <- 1:
			wg.Add(1)
		default:
		}

		go func(cve string) {
			span, spanCtx := tb.TracerLogger.StartSpan(ctx, "RecordedFutureCVELookup", "recordedfuture", "", "cveEnrich")
			span.End(spanCtx)

			defer func() {
				<-threadLimit
				wg.Done()
			}()
			// Calling RF API with metadata switched off
			rfCVEResult, err := rf.EnrichCVE(ctx, m.RFKey, m.RFClient, cve, rf.CVEReportFields, false)
			if err != nil {
				span.AddError(err)
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
func cveMetaDataExtract(rfCVEResults map[string]*rf.CVEReport) []string {
	var triageMetaData, accessVectors []string
	riskCVE := 0
	affectedSystemsCPE := 0

	for cve, data := range rfCVEResults {
		if data == nil {
			triageMetaData = append(triageMetaData, fmt.Sprintf("data doesnt't exist for this cve %s", cve))
			continue
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
func dumpCVECSV(rfCVEResults map[string]*rf.CVEReport) string {
	//Dump data as csv
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	csv.Write([]string{
		"IntelCardLink",
		"Risk Score",
		"Criticality",
		"CriticalityLabel",
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
		"Badness",
	})
	for _, data := range rfCVEResults {
		if data == nil {
			cols := []string{"", "", "", "", "", "", ""}
			csv.Write(cols)
			continue
		}

		// Processing few non string data before adding to CSV
		var threatLists, rawriskRules []string
		for _, threatlist := range data.Data.ThreatLists {
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
			fmt.Sprintf("%.02f", float64(data.Data.Risk.Score)/100.0),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}
