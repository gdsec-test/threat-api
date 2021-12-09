package main

import (
	"bytes"
	"context"
	"encoding/csv"

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

		//Assign operationNAme, operationType, operationSubtype, operationAction properly by the naming standards of Elastic APM
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

//dumpCSV dumps the triage data to CSV
func dumpCSV(sucuriResults map[string]*sucuri.SucuriReport) string {
	//Dump data as csv
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
		"Redirects To:",
	})

	for ioc, data := range sucuriResults {
		if data == nil {
			continue
		}

		//Get Strings from Selected Structs
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

		var totalscore string
		switch data.Ratings.Total.Rating {
		case "A":
			totalscore = "Minimal"
		case "B":
			totalscore = "Low"
		case "C":
			totalscore = "Medium"
		case "D":
			totalscore = "High"
		case "E":
			totalscore = "Critical"
		}

		var secrating string
		switch data.Ratings.Security.Rating {
		case "A":
			secrating = "Minimal"
		case "B":
			secrating = "Low"
		case "C":
			secrating = "Medium"
		case "D":
			secrating = "High"
		case "E":
			secrating = "Critical"
		}

		var domrating string
		switch data.Ratings.Domain.Rating {
		case "A":
			domrating = "Minimal"
		case "B":
			domrating = "Low"
		case "C":
			domrating = "Medium"
		case "D":
			domrating = "High"
		case "E":
			domrating = "Critical"
		}

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
		}
		csv.Write(cols)

	}
	csv.Flush()



	return resp.String()
}
