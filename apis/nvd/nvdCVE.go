package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"sync"

	nvd "github.com/gdcorp-infosec/threat-api/apis/nvd/nvdLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	maxThreadCount = 5
)

// GetNVDData returns the needed data from NVD
func (m *TriageModule) GetNVDData(ctx context.Context, triageRequest *triage.Request) (map[string]*nvd.NVDReport, error) {

	nvdResults := make(map[string]*nvd.NVDReport)

	wg := sync.WaitGroup{}
	nvdLock := sync.Mutex{}
	threadLimit := make(chan int, maxThreadCount)

	for _, cve := range triageRequest.IOCs {
		// Check context
		select {
		case <-ctx.Done():
			break
		case threadLimit <- 1:
			wg.Add(1)
		default:
		}

		// TODO: Assign operationNAme, operationType, operationSubtype, operationAction properly by the naming standards of Elastic APM
		span, spanCtx := tb.TracerLogger.StartSpan(ctx, "NVDLookup", "nvd", "", "nvdCVELookup")

		go func(cve string) {
			defer func() {
				<-threadLimit
				wg.Done()
			}()
			nvdResult, err := nvd.GetNVD(ctx, cve, m.NVDClient)
			if err != nil {
				span.AddError(err)
				nvdLock.Lock()
				nvdResults[cve] = nil // TODO:nil value according to your return data, "", 0 etc
				nvdLock.Unlock()
				return
			}

			nvdLock.Lock()
			nvdResults[cve] = nvdResult
			nvdLock.Unlock()
		}(cve)
		span.End(spanCtx)
	}

	wg.Wait()
	return nvdResults, nil
}

//dumpCSV dumps the triage data to CSV
func dumpCSV(nvdNVDResults map[string]*nvd.NVDReport) string {
	//Dump data as csv
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	csv.Write([]string{
		"CVE",
		"Date Published",
		"Associated CWEs",
		"CVssV3 String",
		"Severity Score",
	})
	for cve, data := range nvdNVDResults {
		if data == nil {
			continue
		}

		for _, result := range data.Result.CVEItems {
			cols := []string{
				cve,
				result.Cve.CVEDataMeta.ID,
				result.PublishedDate,
				result.Cve.Problemtype.ProblemtypeData[0].Description[0].Value,
				result.Impact.BaseMetricV3.CvssV3.VectorString,
				fmt.Sprintf("%f\n", result.Impact.BaseMetricV3.CvssV3.BaseScore),
			}
			csv.Write(cols)
		}
	}
	csv.Flush()

	return resp.String()
}
