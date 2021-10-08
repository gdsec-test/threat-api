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
	var validAccounts, invalidAccounts, catchAllAccounts, spamtrapAccounts, abuseAccounts, doNotMailAccounts, unknownAccounts = 0, 0, 0, 0, 0, 0, 0

	for _, data := range zerobounceResults {
		if data == nil {
			triageMetaData = append(triageMetaData, fmt.Sprintf("Data not found"))
			continue
		}

		// Count the total number of email acocunt types found
		switch {
		case data.Status == "valid":
			validAccounts++
		case data.Status == "invalid":
			invalidAccounts++
		case data.Status == "catch-all":
			catchAllAccounts++
		case data.Status == "spamtrap":
			spamtrapAccounts++
		case data.Status == "abuse":
			abuseAccounts++
		case data.Status == "do_not_mail":
			doNotMailAccounts++
		case data.Status == "unknown":
			unknownAccounts++
		}

	}

	triageMetaData = append(triageMetaData, fmt.Sprintf("Valid account(s): %d, Invalid account(s): %d, Catch-all account(s): %d,"+
		" Spamtrap account(s): %d, Abuse account(s): %d, Do_not_mail account(s): %d, Unkown account(s): %d",
		validAccounts, invalidAccounts, catchAllAccounts, spamtrapAccounts, abuseAccounts, doNotMailAccounts, unknownAccounts))

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
