package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"sync"

	rf "github.com/gdcorp-infosec/threat-api/apis/recordedfuture/recordedfutureLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

// urlReportCreate generates a map of UrlReport from RF API
func (m *TriageModule) urlReportCreate(ctx context.Context, triageRequest *triage.Request) (map[string]*rf.UrlReport, error) {
	rfUrlResults := make(map[string]*rf.UrlReport)

	wg := sync.WaitGroup{}
	rfUrlResultsLock := sync.Mutex{}
	threadLimit := make(chan int, maxThreadCount)

	for _, ioc := range triageRequest.IOCs {
		select {
		case <-ctx.Done():
			break
		case threadLimit <- 1:
			wg.Add(1)
		}

		go func(ioc string) {
			span, spanCtx := tb.TracerLogger.StartSpan(ctx, "RecordedFutureUrlLookup", "recordedfuture", "", "urlEnrich")
			defer span.End(spanCtx)

			defer func() {
				<-threadLimit
				wg.Done()
			}()
			// Calling RF API with metadata switched off
			rfUrlResult, err := rf.EnrichUrl(ctx, m.RFKey, m.RFClient, ioc, rf.UrlReportFields, false)
			if err != nil {
				span.AddError(err)
				rfUrlResultsLock.Lock()
				rfUrlResults[ioc] = nil
				rfUrlResultsLock.Unlock()
				return
			}

			rfUrlResultsLock.Lock()
			rfUrlResults[ioc] = rfUrlResult
			rfUrlResultsLock.Unlock()
		}(ioc)
	}

	wg.Wait()
	return rfUrlResults, nil
}

// urlMetaDataExtract gets the high level insights for a URL
func urlMetaDataExtract(rfUrlResults map[string]*rf.UrlReport) []string {
	triageMetaData := make([]string, 0)

	riskUrl := 0

	for ioc, data := range rfUrlResults {
		if data == nil {
			triageMetaData = append(triageMetaData, fmt.Sprintf("data doesn't exist for this URL: %s", ioc))
			continue
		}

		// Calculate on risk score
		if data.Data.Risk.Score > riskThreshold {
			riskUrl += 1
		}
	}

	if riskUrl > 0 {
		triageMetaData = append(triageMetaData, fmt.Sprintf("%d URLs have a risk score greater than 60", riskUrl))
	}
	return triageMetaData
}

// dumpUrlCSV dumps the triage data to CSV
func dumpUrlCSV(rfUrlResults map[string]*rf.UrlReport) string {
	// Dump data as CSV
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	headers := []string{
		"IoC",
		"Badness",
		"Risk Score",
		"Criticality",
		"CriticalityLabel",
		"First Seen",
		"Last Seen",
	}
	csv.Write(headers)
	for ioc, data := range rfUrlResults {
		if data == nil {
			cols := make([]string, len(headers))
			for i := 0; i < len(headers); i++ {
				cols[i] = ""
			}
			csv.Write(cols)
			continue
		}

		badness := float64(data.Data.Risk.Score) / 100.0
		cols := []string{
			ioc,
			fmt.Sprintf("%.02f", badness),
			fmt.Sprintf("%d", data.Data.Risk.Score),
			fmt.Sprintf("%d", data.Data.Risk.Criticality),
			data.Data.Risk.CriticalityLabel,
			data.Data.Timestamps.FirstSeen.String(),
			data.Data.Timestamps.LastSeen.String(),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}
