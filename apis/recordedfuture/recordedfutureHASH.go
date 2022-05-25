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

//hashReportCreate generates a map of HASHReport from RF API
func (m *TriageModule) hashReportCreate(ctx context.Context, triageRequest *triage.Request) (map[string]*rf.HashReport, error) {
	rfHASHResults := make(map[string]*rf.HashReport)

	wg := sync.WaitGroup{}
	rfHASHResultsLock := sync.Mutex{}
	threadLimit := make(chan int, maxThreadCount)

	for _, hash := range triageRequest.IOCs {
		select {
		case <-ctx.Done():
			break
		case threadLimit <- 1:
			wg.Add(1)
		default:
		}

		go func(hash string) {
			span, spanCtx := tb.TracerLogger.StartSpan(ctx, "RecordedFutureHASHLookup", "recordedfuture", "", "hashEnrich")
			defer span.End(spanCtx)

			defer func() {
				<-threadLimit
				wg.Done()
			}()
			// Calling RF API with metadata switched off
			rfHASHResult, err := rf.EnrichHASH(ctx, m.RFKey, m.RFClient, hash, rf.HASHReportFields, false)
			if err != nil {
				span.AddError(err)
				rfHASHResultsLock.Lock()
				rfHASHResults[hash] = nil
				rfHASHResultsLock.Unlock()
				return
			}

			rfHASHResultsLock.Lock()
			rfHASHResults[hash] = rfHASHResult
			rfHASHResultsLock.Unlock()
		}(hash)
	}

	wg.Wait()
	return rfHASHResults, nil
}

//hashMetaDataExtract gets the high level insights for HASH
func hashMetaDataExtract(rfHASHResults map[string]*rf.HashReport) []string {
	var triageMetaData []string
	riskHASH := 0

	for hash, data := range rfHASHResults {
		if data == nil {
			triageMetaData = append(triageMetaData, fmt.Sprintf("data doesnt't exist for this HASH %s", hash))
			continue
		}

		// Calculate on risk score
		if data.Data.Risk.Score > 60 {
			riskHASH += 1
		}

	}

	if riskHASH > 0 {
		triageMetaData = append(triageMetaData, fmt.Sprintf("%d HASH's have a risk score > 60", riskHASH))
	}

	return triageMetaData
}

//dumpHASHCSV dumps the triage data to CSV
func dumpHASHCSV(rfHASHResults map[string]*rf.HashReport) string {
	//Dump data as csv
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	csv.Write([]string{
		"IntelCardLink",
		"Risk Score",
		"Criticality",
		"CriticalityLabel",
		"First Seen",
		"Last Seen",
		"HashAlgorithm",
		"ThreatLists",
		"FileHashes",
		"Badness",
	})
	for _, data := range rfHASHResults {
		if data == nil {
			continue
		}
		// Processing few non string data before adding to CSV
		var threatLists, fileHashes []string
		for _, threatlist := range data.Data.ThreatLists {
			threatLists = append(threatLists, threatlist.Name)
		}
		for _, hash := range data.Data.FileHashes {
			fileHashes = append(fileHashes, hash)
		}

		cols := []string{
			data.Data.IntelCard,
			fmt.Sprintf("%d", data.Data.Risk.Score),
			fmt.Sprintf("%d", data.Data.Risk.Criticality),
			data.Data.Risk.CriticalityLabel,
			data.Data.Timestamps.FirstSeen.String(),
			data.Data.Timestamps.LastSeen.String(),
			data.Data.HashAlgorithm,
			strings.Join(threatLists, " "),
			strings.Join(fileHashes, "/"),
			fmt.Sprintf("%.02f", float64(data.Data.Risk.Score)/100.0),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}
