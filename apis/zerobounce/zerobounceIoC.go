package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"sync"

	zb "github.com/gdcorp-infosec/threat-api/apis/zerobounce/zerobounceLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	maxThreadCount = 5
)

// Generates a map of email validation data retrieved from zerobounce
func (m *TriageModule) GetZeroBounceData(ctx context.Context, triageRequest *triage.Request) (map[string]*zb.ZeroBounceReport, error) {

	zerobounceResults := make(map[string]*zb.ZeroBounceReport)

	wg := sync.WaitGroup{}
	zerobounceLock := sync.Mutex{}
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

		span, spanCtx := tb.TracerLogger.StartSpan(ctx, "EmailLookup", "zerobounce", "", "zerobounceEmailLookup")

		go func(ioc string) {
			defer func() {
				<-threadLimit
				wg.Done()
			}()
			zerobounceResult, err := zb.GetZeroBounce(ctx, ioc, "", m.ZeroBounceKey, m.ZeroBounceClient)
			if err != nil {
				span.AddError(err)
				zerobounceLock.Lock()
				zerobounceResults[ioc] = nil
				zerobounceLock.Unlock()
				return
			}

			zerobounceLock.Lock()
			zerobounceResults[ioc] = zerobounceResult
			zerobounceLock.Unlock()
		}(ioc)
		span.End(spanCtx)
	}

	wg.Wait()
	return zerobounceResults, nil
}

func zerobounceMetaDataExtract(zerobounceResults map[string]*zb.ZeroBounceReport) []string {
	var triageMetaData []string
	var validEmails, invalidEmails = 0, 0

	for _, data := range zerobounceResults {
		if data == nil {
			triageMetaData = append(triageMetaData, fmt.Sprintf("data not found"))
			continue
		}

		// Count total number of valid and invalid emails
		if data.MxFound == "true" {
			validEmails += 1
		} else {
			invalidEmails += 1
		}

	}

	triageMetaData = append(triageMetaData, fmt.Sprintf("%d valid emails and %d invalid emails found", validEmails, invalidEmails))

	return triageMetaData
}

//dumpCSV dumps the triage data to CSV
func DumpCSV(zerobounceResults map[string]*zb.ZeroBounceReport) string {
	//Dump data as csv
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	csv.Write([]string{
		"Email Address",
		"Status",
		"Sub Status",
		"Free Email",
		"Did You Mean?",
		"Account",
		"Domain",
		"Domain Age Days",
		"SMTP Provider",
		"MX Found?",
		"MX Record",
		"Processed At",
	})
	for _, data := range zerobounceResults {
		if data == nil {
			cols := []string{"", "", "", "", "", "", ""}
			csv.Write(cols)
			continue
		}

		// Convert results to string
		cols := []string{
			data.Email,
			data.Status,
			data.SubStatus,
			fmt.Sprint(data.FreeEmail),
			fmt.Sprint(data.DidYouMean),
			data.Account,
			data.Domain,
			data.DomainAgeDays,
			data.SmtpProvider,
			data.MxFound,
			data.MxRecord,
			data.ProcessedAt,
		}
		csv.Write(cols)

	}
	csv.Flush()

	return resp.String()
}
