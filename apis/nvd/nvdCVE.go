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
				nvdResults[cve] = nil
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

//cveMetaDataExtract gets the high level insights for CVE
func cveMetaDataExtract(nvdResults map[string]*nvd.NVDReport) []string {
	var triageMetaData []string
	riskCVE := 0

	for cve, data := range nvdResults {
		if data == nil {
			triageMetaData = append(triageMetaData, fmt.Sprintf("data doesnt't exist for this cve %s", cve))
			continue
		}

		// Calculate on risk score
		if data.Result.CVEItems[0].Impact.BaseMetricV3.CvssV3.BaseScore >= 7.0 {
			riskCVE += 1
		}

	}

	if riskCVE > 0 {
		triageMetaData = append(triageMetaData, fmt.Sprintf("%d CVE's have a base score > 7.0, implying high or critical severity", riskCVE))
	}

	//fmt.Println(triageMetaData)
	return triageMetaData
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
		"CVSS v3 String",
		"Severity Score",
	})

	for _, data := range nvdNVDResults {
		if data == nil {
			continue
		}

		for _, result := range data.Result.CVEItems {
			var cpes string
			for _, node := range result.Configurations.Nodes {
				for _, cpe := range node.CpeMatch {
					cpes = cpes + cpe.Cpe23URI + " "
				}
			}

			cols := []string{
				result.Cve.CVEDataMeta.ID,
				result.PublishedDate,
				result.Cve.Problemtype.ProblemtypeData[0].Description[0].Value,
				result.Impact.BaseMetricV3.CvssV3.VectorString,
				fmt.Sprintf("%f", result.Impact.BaseMetricV3.CvssV3.BaseScore),
				cpes,
			}
			csv.Write(cols)
		}
	}
	csv.Flush()

	return resp.String()
}
