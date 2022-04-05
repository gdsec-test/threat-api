package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	tn "github.com/gdcorp-infosec/threat-api/apis/tanium/taniumLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
	"sync"
)

const (
	maxThreadCount = 5
	rowLimit       = 100

	installedSoftwareQuestion = "Get Installed Applications from all machines with Computer Name matches %s"
)

func (m *TriageModule) returnTaniumClient() tn.TaniumClient {
	// TODO: Set Auth data from triagemodule to TaniumClient
	// TODO: Add in extra data required for Tanium Authentication
	// Returning an empty client for now
	return tn.TaniumClient{}
}

// GetProgramsFromGodaddyMachines returns the Tanium results for the questions that are queried
func (m *TriageModule) GetProgramsFromGodaddyMachines(ctx context.Context, triageRequest *triage.Request) (map[string]chan tn.Row, error) {

	taniumResults := make(map[string]chan tn.Row)

	wg := sync.WaitGroup{}
	taniumLock := sync.Mutex{}
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

		span, spanCtx := tb.TracerLogger.StartSpan(ctx, "TaniumIoCLookup", "tanium", "", "taniumIoCLookup")

		go func(ioc string) {
			defer func() {
				<-threadLimit
				wg.Done()
			}()
			currentInstalledSoftwareQuestion := fmt.Sprintf(installedSoftwareQuestion, ioc)
			_, taniumResult, err := m.performTaniumSearch(ctx, currentInstalledSoftwareQuestion)
			if err != nil {
				span.AddError(err)
				taniumLock.Lock()
				taniumResults[ioc] = nil
				taniumLock.Unlock()
				return
			}

			taniumLock.Lock()
			taniumResults[ioc] = taniumResult
			taniumLock.Unlock()
		}(ioc)
		span.End(spanCtx)
	}

	wg.Wait()

	return taniumResults, nil
}

// performTaniumSearch given a Tanium question, create the question, wait for rowLimit results (or some maximum) to be available in Tanium, and return the column names, a channel of results, and an error if present

func (m *TriageModule) performTaniumSearch(ctx context.Context, questionString string) ([]string, chan tn.Row, error) {
	c := m.returnTaniumClient()

	parsable, err := c.CanParse(ctx, questionString)
	if err != nil {
		return nil, nil, err
	} else if !parsable {
		return nil, nil, fmt.Errorf("question not parsable")
	}

	question, err := c.CreateQuestion(ctx, questionString)
	if err != nil {
		return nil, nil, err
	}

	cols, err := question.GetColumns(context.Background())
	if err != nil {
		return nil, nil, err
	}

	columns := make([]string, 0)

	// Get the names of all columns from the Tanium question
	for _, b := range cols {
		columns = append(columns, b.Name)
	}

	err = question.WaitForResults(ctx, rowLimit)
	if err != nil {
		return nil, nil, err
	}

	results, err := question.GetResults(ctx)
	if err != nil {
		return nil, nil, err
	}

	return columns, results, nil

}

//dumpCSV dumps the triage data to CSV
func dumpCSV(taniumResults map[string]chan tn.Row) string {
	//Dump data as csv
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	csv.Write([]string{
		"Machine Name",
		"Data",
	})
	for ioc, row := range taniumResults {

		if row == nil {
			continue
		}

		var rowOutputData string

		for data := range row {
			for _, r := range data.Data {
				rowOutputData = rowOutputData + " " + r.String()
			}
		}

		cols := []string{
			ioc,
			rowOutputData,
		}
		csv.Write(cols)

	}
	csv.Flush()

	return resp.String()
}
