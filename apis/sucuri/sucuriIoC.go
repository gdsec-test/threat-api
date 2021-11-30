package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"

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

			//Secret Handling:
			//sucuriResult, err := sucuri.GetSucuri(ctx, ioc, m.Sucuri, m.SucuriKeyy, m.SucuriClient)
			sucuriResult, err := sucuri.GetSucuri(ctx, ioc, m.SucuriClient)
			if err != nil {
				span.AddError(err)
				sucuriLock.Lock()
				sucuriResults[ioc] = nil // TODO:nil value according to your return data, "", 0 etc
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
		"Risk Score",
		"BlackList Info",
		"Links: JSLOCAL",
		"Links: URL",
		"Recommendations",
		"Scan: Domain",
		"Scan: IP",
		"Scan: Site",
		"System: Info",
		"System: Notice",
		"Version: Build Date",
		"Version: Compiled Date",
		"Version: DB Date",
		"Version: Version",


	})
	for ioc, data := range sucuriResults {
		if data == nil {
			continue
		}

		//Calculate Risk Score
		fmt.Println("Len of Blacklist Info")
		fmt.Println(len(data.BLACKLIST.WARN))
		fmt.Println(len(data.MALWARE.WARN))
		var blacklist_score float32
		if len(data.BLACKLIST.WARN) >= 2 {
			blacklist_score = 1.0
		} else if len(data.BLACKLIST.WARN) == 1 {
			blacklist_score = 0.5
		} else {
			blacklist_score = 0.0
		}
		var malware_score float32
		if len(data.MALWARE.WARN) >= 1 {
			malware_score = 1.0
		} else {
			malware_score = 0.0
		}
		//var risk_score float32
		risk_score := 0.33 * blacklist_score + 0.67 * malware_score
		risksc := fmt.Sprintf("%f", risk_score)

		fmt.Println("Risk Score")
		fmt.Println(risk_score)
		fmt.Println(blacklist_score)
		fmt.Println(malware_score)

		//Format Sucuri Output for Printing
		var blacklisted string
		for _, blacklistouter := range data.BLACKLIST.INFO {
			for _, blacklistinner := range blacklistouter {
				blacklisted = blacklisted + blacklistinner + "\n"
			}
		}
		fmt.Println(blacklisted)

		var recs string
		for _, recsouter := range data.RECOMMENDATIONS {
			for _, recsinner := range recsouter {
				recs = recs + recsinner + "\n"
			}
		}
		fmt.Println(recs)

		var scans string
		for _, scanouter := range data.SCAN.DOMAIN {
			scans = "Domains:" + scans + scanouter + "\n"
		}
		fmt.Println(scans)

		var mals string
		for _, malouter := range data.MALWARE.WARN {
			for _, malinner := range malouter {
				mals = mals + malinner + "\n"
			}
		}
		fmt.Println(mals)


		cols := []string{
			risksc,
			ioc,
			recs,
			scans,
			blacklisted,
			//data.BLACKLIST.INFO[0][0],
			//data.LINKS.JSLOCAL[0],
		}
		csv.Write(cols)

		//Test to Check if Data is passed
		/* csv.Write(cols)
		print("IOC", "/n")
		print(cols[0], "/n")
		print("Blacklist Info", "/n")
		print(cols[1], "/n")
		print("Links", "/n")
		print(cols[2], "/n") */


	}
	csv.Flush()


	return resp.String()
}
