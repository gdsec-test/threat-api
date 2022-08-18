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
	MD5_LENGTH    = 32
	SHA1_LENGTH   = 40
	SHA256_LENGTH = 64
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

// Recorded Future returns hashes for the same file as an array
// of three strings, not noting which is which. sortHashes sorts
// the hashes based on length and returns them in MD5, SHA1,
// SHA256 order.
func sortHashes(hash_list []string) (string, string, string) {
	if hash_list == nil || len(hash_list) != 3 {
		fmt.Print("Input hash list was not valid")
		return "", "", ""
	}

	md5 := ""
	sha1 := ""
	sha256 := ""

	for _, hash := range hash_list {
		if len(hash) == MD5_LENGTH {
			md5 = hash
		} else if len(hash) == SHA1_LENGTH {
			sha1 = hash
		} else if len(hash) == SHA256_LENGTH {
			sha256 = hash
		} else {
			fmt.Printf("Not a recognized hash length: \"%s\" (%d)", hash, len(hash))
		}
	}

	return md5, sha1, sha256
}

//dumpHASHCSV dumps the triage data to CSV
func dumpHASHCSV(rfHASHResults map[string]*rf.HashReport) string {
	//Dump data as csv
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	headers := []string{
		"IoC",
		"Badness",
		"MD5",
		"SHA1",
		"SHA256",
		"IntelCardLink",
		"Risk Score",
		"Criticality",
		"CriticalityLabel",
		"First Seen",
		"Last Seen",
		"HashAlgorithm",
		"ThreatLists",
	}
	csv.Write(headers)
	for ioc, data := range rfHASHResults {
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
		md5, sha1, sha256 := sortHashes(data.Data.FileHashes)

		badness := float64(data.Data.Risk.Score) / 100.0
		cols := []string{
			ioc,
			fmt.Sprintf("%.02f", badness),
			md5,
			sha1,
			sha256,
			data.Data.IntelCard,
			fmt.Sprintf("%d", data.Data.Risk.Score),
			fmt.Sprintf("%d", data.Data.Risk.Criticality),
			data.Data.Risk.CriticalityLabel,
			data.Data.Timestamps.FirstSeen.String(),
			data.Data.Timestamps.LastSeen.String(),
			data.Data.HashAlgorithm,
			strings.Join(threatLists, " "),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}
