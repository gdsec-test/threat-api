package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"strings"
	"sync"

	us "github.com/gdcorp-infosec/threat-api/apis/urlscanio/urlscanioLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	maxThreadCount = 5
)

// Submits URL to urlscan.io and retrieves results of scan
func (m *TriageModule) GetURLScanData(ctx context.Context, triageRequest *triage.Request, metaData *us.MetaData) (map[string]*us.ResultHolder, error) {

	urlscanioResults := make(map[string]*us.ResultHolder)

	wg := sync.WaitGroup{}
	urlscanioLock := sync.Mutex{}
	threadLimit := make(chan int, maxThreadCount)

	for _, ioc := range triageRequest.IOCs {
		// Check context
		select {
		case <-ctx.Done():
			break
		case threadLimit <- 1:
			wg.Add(1)
		default:
		}

		// Log spans in Elastic APM
		span, spanCtx := tb.TracerLogger.StartSpan(ctx, "URLScan", "urlscanio", "", "urlscanIoCLookup")

		go func(ioc string) {
			defer func() {
				<-threadLimit
				wg.Done()
			}()
			urlscanioResult, err := us.GetURLScanResults(ctx, ioc, m.urlscanKey, m.urlscanClient)
			if err != nil && strings.Contains(err.Error(), "400") {
				metaData.BlacklistedDomainsCount++
				metaData.BlacklistedDomains += ioc + " "
				err = nil
			} else if err != nil && strings.Contains(err.Error(), "404") {
				metaData.URLsNotFoundCount++
				metaData.URLsNotFound += ioc + " "
			} else if err != nil {
				span.AddError(err)
				urlscanioLock.Lock()
				urlscanioResults[ioc] = nil
				urlscanioLock.Unlock()
			} else {
				urlscanioLock.Lock()
				urlscanioResults[ioc] = urlscanioResult
				urlscanioLock.Unlock()
			}

		}(ioc)
		span.End(spanCtx)
	}

	wg.Wait()
	return urlscanioResults, nil
}

//dumpCSV dumps the triage data to CSV
func dumpCSV(urlscanioResults map[string]*us.ResultHolder, metaData *us.MetaData) string {
	//Dump data as csv
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	csv.Write([]string{
		"URL",
		"Screenshot URL",
		"Overall Verdict Malicious",
		"Overall Verdict Score",
		"Overall Verdicts",
		"Urlscan Verdict Score",
		"Urlscan Verdict Malicious",
		"Engines Verdict Score",
		"Engines Verdict Malicious Total",
		"Engines Verdict Benign Total",
		"Engines Verdict Engines Total",
		"Community Verdict Score",
		"Community Votes Malicious",
		"Community Votes Benign",
		"Community Votes Total",
		"Report URL",
	})

	for _, data := range urlscanioResults {
		if data == nil {
			continue
		}

		cols := []string{
			data.Page.Url,
			data.Task.ScreenshotURL,
			fmt.Sprintf("%v", data.Verdicts.Overall.Malicious),
			fmt.Sprintf("%v", data.Verdicts.Overall.Score),
			fmt.Sprintf("%v", data.Verdicts.Overall.HasVerdicts),
			fmt.Sprintf("%v", data.Verdicts.Urlscan.Score),
			fmt.Sprintf("%v", data.Verdicts.Urlscan.Malicious),
			fmt.Sprintf("%v", data.Verdicts.Engines.Score),
			fmt.Sprintf("%v", data.Verdicts.Engines.MaliciousTotal),
			fmt.Sprintf("%v", data.Verdicts.Engines.BenignTotal),
			fmt.Sprintf("%v", data.Verdicts.Engines.EnginesTotal),
			fmt.Sprintf("%v", data.Verdicts.Community.Score),
			fmt.Sprintf("%v", data.Verdicts.Community.VotesMalicious),
			fmt.Sprintf("%v", data.Verdicts.Community.VotesBenign),
			fmt.Sprintf("%v", data.Verdicts.Community.VotesTotal),
			data.Task.ReportURL,
		}
		csv.Write(cols)

		if data.Verdicts.Overall.Malicious || data.Verdicts.Urlscan.Malicious || data.Verdicts.Engines.MaliciousTotal > 0 || data.Verdicts.Community.VotesMalicious > 0 {
			metaData.MaliciousURLsCount++
			metaData.MaliciousURLs += data.Page.Url + " "
		}
	}
	csv.Flush()

	return resp.String()
}

func urlscanMetaDataExtract(metaData *us.MetaData) []string {
	var triageMetaData []string
	triageMetaData = append(triageMetaData, fmt.Sprintf("Malicious URL(s) Found: %d", metaData.MaliciousURLsCount))
	triageMetaData = append(triageMetaData, fmt.Sprintf("\nMalicious URL(s): %s", metaData.MaliciousURLs))
	triageMetaData = append(triageMetaData, fmt.Sprintf("\nBlacklisted Domain(s) Found %d", metaData.BlacklistedDomainsCount))
	triageMetaData = append(triageMetaData, fmt.Sprintf("\nBlacklisted Domain(s) Found %s", metaData.BlacklistedDomains))
	triageMetaData = append(triageMetaData, "\nurlscan.io Submission API used is rate-limited to 5000 public scans per day, 500 per hour and 60 per minute. Result API is rate-limited to 120 requests per minute, 5000 per hour and 10000 per day.")
	return triageMetaData
}
