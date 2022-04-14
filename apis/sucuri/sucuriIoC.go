package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"strconv"

	"sync"

	sucuri "github.com/gdcorp-infosec/threat-api/apis/sucuri/sucuriLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	maxThreadCount = 5
)

// GetSucuriData returns data from Sucuri
func (m *TriageModule) GetSucuriData(ctx context.Context, triageRequest *triage.Request) (map[string]*sucuri.SucuriReport, error) {

	sucuriResults := make(map[string]*sucuri.SucuriReport)

	wg := sync.WaitGroup{}
	sucuriLock := sync.Mutex{}
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

		// Assign operationNAme, operationType, operationSubtype, operationAction properly by the naming standards of Elastic APM
		span, spanCtx := tb.TracerLogger.StartSpan(ctx, "SucuriLookup", "sucuri", "", "sucuriIoCLookup")

		go func(ioc string) {
			defer func() {
				<-threadLimit
				wg.Done()
			}()

			sucuriResult, err := sucuri.GetSucuri(ctx, ioc, m.SucuriClient)
			if err != nil {
				span.AddError(err)
				sucuriLock.Lock()
				sucuriResults[ioc] = nil
				sucuriLock.Unlock()
				return
			}

			sucuriLock.Lock()
			sucuriResults[ioc] = sucuriResult
			sucuriLock.Unlock()
		}(ioc)
		span.End(spanCtx)
	}

	wg.Wait()
	return sucuriResults, nil
}

// dumpCSV dumps the triage data to CSV
func dumpCSV(sucuriResults map[string]*sucuri.SucuriReport) string {
	// Dump data as csv
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	csv.Write([]string{
		"Domain",
		"Total Rating Label",
		"Total Rating Score",
		"Security Rating Label",
		"Security Rating Score",
		"Domain Rating Label",
		"Domain Rating Score",
		"Suspicious Activity",
		"Details",
		"Redirects To",
		"Badness",
	})

	ratingToLongForm := map[string]string{
		"A": "Minimal",
		"B": "Low",
		"C": "Medium",
		"D": "High",
		"E": "Critical",
	}
	ratingToBadness := map[string]float64{
		"A": 0.00,
		"B": 0.17,
		"C": 0.50,
		"D": 0.83,
		"E": 1.00,
	}

	for ioc, data := range sucuriResults {
		if data == nil {
			continue
		}

		// Get Strings from Selected Structs
		var msgs string
		var details string
		for _, malouter := range data.Warnings.Security.Malware {
			msgs = msgs + malouter.Msg + "\n"
			details = details + malouter.Details + "\n"
		}

		var redirects string
		for _, reds := range data.Site.RedirectsTo {
			redirects = redirects + reds + "\n"
		}

		// Convert the single-letter ratings into more verbose words and a float score value
		totalscore := ratingToLongForm[data.Ratings.Total.Rating]
		secrating := ratingToLongForm[data.Ratings.Security.Rating]
		domrating := ratingToLongForm[data.Ratings.Domain.Rating]
		badness := ratingToBadness[data.Ratings.Total.Rating]

		cols := []string{
			ioc,
			totalscore,
			data.Ratings.Total.Rating,
			secrating,
			data.Ratings.Security.Rating,
			domrating,
			data.Ratings.Domain.Rating,
			msgs,
			details,
			redirects,
			strconv.FormatFloat(badness, 'f', 2, 64),
		}
		csv.Write(cols)

	}
	csv.Flush()

	return resp.String()
}
