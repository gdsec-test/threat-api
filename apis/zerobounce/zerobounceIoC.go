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
	ioc_list := `"email_batch":[`

	for _, ioc := range triageRequest.IOCs {
		ioc_list += fmt.Sprintf(`{"email_address": "%s"},`, ioc)
	}
	ioc_list += "]"

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

	wg.Wait()
	return zerobounceResults, nil
}


func zerobounceMetaDataExtract(zerobounceResults map[string]*zb.ZeroBounceReport, metaData *zb.MetaData) []string {

	var triageMetaData []string

	triageMetaData = append(triageMetaData, fmt.Sprintf("Valid account(s): %d, Invalid account(s): %d, Catch-all account(s): %d,"+
		" Spamtrap account(s): %d, Abuse account(s): %d, Do_not_mail account(s): %d, Unkown account(s): %d", metaData.ValidAccounts, metaData.InvalidAccounts, metaData.CatchAllAccounts, metaData.SpamTrapAccounts, metaData.AbuseAccounts, metaData.DoNotMailAccounts, metaData.UnkownAccounts))
	triageMetaData = append(triageMetaData, "\nZerobounce API is rate-limited to allow 5 requests per minute with a maximum of 100 emails per request. In case no data is found, the rate limit has been exceeded. Try again in 10 minutes.")

	return triageMetaData
}

//dumpCSV dumps the triage data to CSV
func DumpCSV(zerobounceResults map[string]*zb.ZeroBounceReport, metaData *zb.MetaData) string {
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

			// Count the total number of email acocunt types found
			switch {
			case email.Status == "valid":
				metaData.ValidAccounts++
			case email.Status == "invalid":
				metaData.InvalidAccounts++
			case email.Status == "catch-all":
				metaData.CatchAllAccounts++
			case email.Status == "spamtrap":
				metaData.SpamTrapAccounts++
			case email.Status == "abuse":
				metaData.AbuseAccounts++
			case email.Status == "do_not_mail":
				metaData.DoNotMailAccounts++
			case email.Status == "unknown":
				metaData.UnkownAccounts++
			}
		}
	}
	csv.Flush()
	return resp.String()
}
