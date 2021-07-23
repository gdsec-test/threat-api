package main

import (
	"bytes"
	"context"
	"encoding/csv"
	eg "github.com/gdcorp-infosec/threat-api/example-api-module/exampleLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
	"sync"
)

const (
	maxThreadCount = 5 //TODO: Adjust the count according to your service
)

// GetExampleData returns the needed data TODO: Provide the description in brief
// Create the required return data structure from what the service API provides
func (m *TriageModule) GetExampleData(ctx context.Context, triageRequest *triage.Request) (map[string]*eg.EgReport, error) {

	exampleResults := make(map[string]*eg.EgReport) //TODO: Create the return structure accordingly

	wg := sync.WaitGroup{}
	egLock := sync.Mutex{}
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

		// TODO: Assign operationNAme, operationType, operationSubtype, operationAction properly by the naming standards of Elastic APM
		span, spanCtx := tb.TracerLogger.StartSpan(ctx, "EgLookup", "passivetotal", "", "passiveDNSLookup")

		go func(ioc string) {
			defer func() {
				<-threadLimit
				wg.Done()
			}()
			exampleResult, err := eg.GetExampleIoCEnrich(ctx, ioc, m.ExampleUser, m.ExampleKey, m.PTClient)
			if err != nil {
				span.AddError(err)
				egLock.Lock()
				exampleResults[ioc] = nil // TODO:nil value according to your return data, "", 0 etc
				egLock.Unlock()
				return
			}

			egLock.Lock()
			exampleResults[ioc] = exampleResult
			egLock.Unlock()
		}(ioc)
		span.End(spanCtx)
	}

	wg.Wait()
	return exampleResults, nil
}

//dumpCSV dumps the triage data to CSV
func dumpCSV(egResults map[string]*eg.EgReport) string {
	//Dump data as csv
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	csv.Write([]string{
		"IoC",
		"Column1",
		"Column2",
	})
	for ioc, data := range egResults {
		if data == nil {
			continue
		}

		// TODO: Iterate the data according to your return data
		cols := []string{
			// TODO: Convert your datatype  to string
			ioc,
			"column1 data in string",
			"column2 data in string",
		}
		csv.Write(cols)

	}
	csv.Flush()

	return resp.String()
}
