package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"sync"
	"time"

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
	ioc_list := "\"email_batch\":["

	for _, ioc := range triageRequest.IOCs {
		ioc_list += "{\"email_address\": \"" + ioc + "\"},"
	}
	ioc_list += "]"

	//for _, ioc := range triageRequest.IOCs {
	// Check context
	select {
	case <-ctx.Done():
		break
	case threadLimit <- 1:
		wg.Add(1)
	default:
	}

	span, spanCtx := tb.TracerLogger.StartSpan(ctx, "EmailLookup", "zerobounce", "", "zerobounceEmailLookup")

	go func(ioc_list string) {
		defer func() {
			<-threadLimit
			wg.Done()
		}()
		zerobounceResult, err := zb.GetZeroBounce(ctx, ioc_list, "", m.ZeroBounceKey, m.ZeroBounceClient)
		if err != nil {
			span.AddError(err)
			zerobounceLock.Lock()
			zerobounceResults[ioc_list] = nil
			zerobounceLock.Unlock()
			return
		}

		zerobounceLock.Lock()
		zerobounceResults[ioc_list] = zerobounceResult
		zerobounceLock.Unlock()

		time.Sleep(2 * time.Second)
	}(ioc_list)
	span.End(spanCtx)
	//}

	wg.Wait()
	return zerobounceResults, nil
}

func zerobounceMetaDataExtract(zerobounceResults map[string]*zb.ZeroBounceReport) []string {
	var triageMetaData []string
	var validAccounts, invalidAccounts, catchAllAccounts, spamtrapAccounts, abuseAccounts, doNotMailAccounts, unknownAccounts = 0, 0, 0, 0, 0, 0, 0

	for _, response := range zerobounceResults {
		if response == nil {
			triageMetaData = append(triageMetaData, "Data not found")
			continue
		}

		for _, data := range response.EmailBatch {
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
	}

	triageMetaData = append(triageMetaData, fmt.Sprintf("Valid account(s): %d, Invalid account(s): %d, Catch-all account(s): %d,"+
		" Spamtrap account(s): %d, Abuse account(s): %d, Do_not_mail account(s): %d, Unkown account(s): %d",
		validAccounts, invalidAccounts, catchAllAccounts, spamtrapAccounts, abuseAccounts, doNotMailAccounts, unknownAccounts))
	triageMetaData = append(triageMetaData, "\nZerobounce API is rate-limited to allow 5 requests per minute with a maximum of 100 emails per request. In case no data is found, the rate limit has been exceeded. Try again in 10 minutes.")

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
			cols := []string{"", "", "", "", "", "", "", "", "", "", "", ""}
			csv.Write(cols)
			continue
		}

		for _, email := range data.EmailBatch {
			// Convert results to string
			cols := []string{
				email.Address,
				email.Status,
				email.SubStatus,
				fmt.Sprint(email.FreeEmail),
				fmt.Sprint(email.DidYouMean),
				email.Account,
				email.Domain,
				email.DomainAgeDays,
				email.SMTPProvider,
				email.MxFound,
				email.MxRecord,
				email.ProcessedAt,
			}
			csv.Write(cols)
		}

	}
	csv.Flush()
	return resp.String()
}
