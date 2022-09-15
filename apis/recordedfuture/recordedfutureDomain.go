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
	riskThreshold = 60
)

// domainReportCreate generates a map of DomainReport from RF API
func (m *TriageModule) domainReportCreate(ctx context.Context, triageRequest *triage.Request) (map[string]*rf.DomainReport, error) {
	rfDomainResults := make(map[string]*rf.DomainReport)

	wg := sync.WaitGroup{}
	rfDomainResultsLock := sync.Mutex{}
	threadLimit := make(chan int, maxThreadCount)

	for _, domain := range triageRequest.IOCs {
		select {
		case <-ctx.Done():
			break
		case threadLimit <- 1:
			wg.Add(1)
		}

		go func(domain string) {
			span, spanCtx := tb.TracerLogger.StartSpan(ctx, "RecordedFutureDomainLookup", "recordedfuture", "", "domainEnrich")
			defer span.End(spanCtx)

			defer func() {
				<-threadLimit
				wg.Done()
			}()
			// Calling RF API with metadata switched off
			rfDomainResult, err := rf.EnrichDomain(ctx, m.RFKey, m.RFClient, domain, rf.DomainReportFields, false)
			if err != nil {
				span.AddError(err)
				rfDomainResultsLock.Lock()
				rfDomainResults[domain] = nil
				rfDomainResultsLock.Unlock()
				return
			}

			rfDomainResultsLock.Lock()
			rfDomainResults[domain] = rfDomainResult
			rfDomainResultsLock.Unlock()
		}(domain)
	}

	wg.Wait()
	return rfDomainResults, nil
}

// domainMetaDataExtract gets the high level insights for a domain
func domainMetaDataExtract(rfDomainResults map[string]*rf.DomainReport) []string {
	triageMetaData := make([]string, 0)

	riskDomain := 0

	for domain, data := range rfDomainResults {
		if data == nil {
			triageMetaData = append(triageMetaData, fmt.Sprintf("data doesn't exist for this domain %s", domain))
			continue
		}

		// Calculate on risk score
		if data.Data.Risk.Score > riskThreshold {
			riskDomain += 1
		}
	}

	if riskDomain > 0 {
		triageMetaData = append(triageMetaData, fmt.Sprintf("%d domain addresses have a risk score greater than 60", riskDomain))
	}
	return triageMetaData
}

// dumpDomainCSV dumps the triage data to CSV
func dumpDomainCSV(rfDomainResults map[string]*rf.DomainReport) string {
	// Dump data as CSV
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
	for ioc, data := range rfDomainResults {
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
