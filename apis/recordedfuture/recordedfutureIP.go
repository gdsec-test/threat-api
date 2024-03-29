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

// cveReportCreate generates a map of CVEReport from RF API
func (m *TriageModule) ipReportCreate(ctx context.Context, triageRequest *triage.Request) (map[string]*rf.IPReport, error) {
	rfIPResults := make(map[string]*rf.IPReport)

	wg := sync.WaitGroup{}
	rfIPResultsLock := sync.Mutex{}
	threadLimit := make(chan int, maxThreadCount)

	for _, ip := range triageRequest.IOCs {
		select {
		case <-ctx.Done():
			break
		case threadLimit <- 1:
			wg.Add(1)
		}

		go func(ip string) {
			span, spanCtx := tb.TracerLogger.StartSpan(ctx, "RecordedFutureIPLookup", "recordedfuture", "", "ipEnrich")
			defer span.End(spanCtx)

			defer func() {
				<-threadLimit
				wg.Done()
			}()
			// Calling RF API with metadata switched off
			rfIPResult, err := rf.EnrichIP(ctx, m.RFKey, m.RFClient, ip, rf.IPReportFields, false)
			if err != nil {
				span.AddError(err)
				rfIPResultsLock.Lock()
				rfIPResults[ip] = nil
				rfIPResultsLock.Unlock()
				return
			}

			rfIPResultsLock.Lock()
			rfIPResults[ip] = rfIPResult
			rfIPResultsLock.Unlock()
		}(ip)
	}

	wg.Wait()
	return rfIPResults, nil
}

// ipMetaDataExtract gets the high level insights for IP
func ipMetaDataExtract(rfIPResults map[string]*rf.IPReport) []string {
	triageMetaData := make([]string, 0)
	riskyCIDRIPs := make(map[string]int)

	riskIP := 0

	for ip, data := range rfIPResults {
		if data == nil {
			triageMetaData = append(triageMetaData, fmt.Sprintf("data doesnt't exist for this ip %s", ip))
			continue
		}

		// Keep the count of risky CIDR IP
		if len(data.Data.RiskyCIDRIPs) > 0 {
			riskyCIDRIPs[ip] = len(data.Data.RiskyCIDRIPs)
		}

		// Calculate on risk score
		if data.Data.Risk.Score > 60 {
			riskIP += 1
		}
	}

	// Add the final results to Metadata
	if len(riskyCIDRIPs) > 0 {
		for ip, count := range riskyCIDRIPs {
			triageMetaData = append(triageMetaData, fmt.Sprintf("%d risky IP addresses in same CIDR block as %s", count, ip))
		}
	}

	if riskIP > 0 {
		triageMetaData = append(triageMetaData, fmt.Sprintf("%d IP addresses have a risk score greater than 60", riskIP))
	}
	return triageMetaData
}

// dumpIPCSV dumps the triage data to CSV
func dumpIPCSV(rfIPResults map[string]*rf.IPReport) string {
	//Dump data as csv
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	headers := []string{
		"IoC",
		"Badness",
		"IntelCardLink",
		"Risk Score",
		"Criticality",
		"CriticalityLabel",
		"First Seen",
		"Last Seen",
		"ThreatLists",
	}
	csv.Write(headers)
	for ioc, data := range rfIPResults {
		if data == nil {
			cols := make([]string, len(headers))
			for i := 0; i < len(headers); i++ {
				cols[i] = ""
			}
			csv.Write(cols)
			continue
		}
		// Processing few non string data before adding to CSV
		var threatLists []string
		for _, threatlist := range data.Data.ThreatLists {
			threatLists = append(threatLists, threatlist.Name)
		}

		badness := float64(data.Data.Risk.Score) / 100.0
		cols := []string{
			ioc,
			fmt.Sprintf("%.02f", badness),
			data.Data.IntelCard,
			fmt.Sprintf("%d", data.Data.Risk.Score),
			fmt.Sprintf("%d", data.Data.Risk.Criticality),
			data.Data.Risk.CriticalityLabel,
			data.Data.Timestamps.FirstSeen.String(),
			data.Data.Timestamps.LastSeen.String(),
			strings.Join(threatLists, " "),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}
