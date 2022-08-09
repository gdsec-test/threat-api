package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	// "github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	APIvoidEndpoint     = "https://endpoint.apivoid.com/%s/v1/pay-as-you-go/?%s=%s&key=%s"
	limiterMilliseconds = 333
)

// GetAPIVoidData queries APIVoid's IP Reputation data and returns enriched results
func (m *TriageModule) GetAPIVoidData(ctx context.Context, triageRequest *triage.Request) (map[string]*APIvoidReport, error) {

	apivoidResults := make(map[string]*APIvoidReport)

	apivoidLock := sync.Mutex{}

	// insert all iocs into a channel for rate limiting
	iocs := make(chan string, len(triageRequest.IOCs))
	for _, ioc := range triageRequest.IOCs {
		iocs <- ioc
	}
	close(iocs)

	// APIVoid developer docs suggest sending not more than 2-3 requests/second
	// implementing a limiter to send a request to APIVoid every 333ms which is ~3 req/sec
	limiter := time.Tick(limiterMilliseconds * time.Millisecond)
	for ioc := range iocs {
		<-limiter
		span, spanCtx := tb.TracerLogger.StartSpan(ctx, "APIVoidLookup", "apivoid", "", "apivoidIoCLookup")
		apivoidResult, err := GetAPIVoidReport(ctx, ioc, m.APIVoidClient, triageRequest.IOCsType, m.APIVoidKey)
		if err != nil {
			span.AddError(err)
			apivoidLock.Lock()
			apivoidResults[ioc] = nil
			apivoidLock.Unlock()
			span.End(spanCtx)
			continue
		}

		apivoidLock.Lock()
		apivoidResults[ioc] = apivoidResult
		apivoidLock.Unlock()

		span.End(spanCtx)

	}
	return apivoidResults, nil
}

//dumpCSV dumps the triage data to CSV
func dumpCSV(apivoidResults map[string]*APIvoidReport, iocType triage.IOCType) string {
	//Dump data as csv
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	headers := []string{
		"IoC",
		"BL Engine",
		"Blacklisted",
	}
	if iocType == triage.DomainType {
		headers = append(headers, "Confidence")
	}
	csv.Write(headers)

	for ioc, data := range apivoidResults {
		if data == nil {
			continue
		}
		var cols []string
		var engines interface{}
		if iocType == triage.IPType || iocType == triage.DomainType {
			engines = data.Data.Report.Blacklist.Engines
		} else {
			engines = data.Data.Report.DomainBlacklist.Engines
		}
		for _, engine := range engines.(BlackListEngines) {
			var engineName string
			if iocType != triage.URLType {
				engineName = engine.Engine
			} else {
				engineName = engine.Name
			}
			cols = []string{
				ioc,
				engineName + ":" + engine.Reference,
				fmt.Sprintf("%v", engine.Detected),
			}
			if iocType == triage.DomainType {
				cols = append(cols, engine.Confidence)
			}
			csv.Write(cols)
		}
		if iocType == triage.URLType {
			csv.Write([]string{"DNS Records"})
			csv.Write([]string{
				"IoC",
				"DNS Type",
				"DNS Target",
				"DNS IP",
				"DNS ISP",
				"DNS Address",
			})
			for _, dnsRecord := range data.Data.Report.DNSRecords.Ns.Records {
				csv.Write([]string{
					ioc,
					"NS",
					dnsRecord.Target,
					dnsRecord.IP,
					dnsRecord.Isp,
					dnsRecord.CountryCode + ":" + dnsRecord.CountryName,
				})
			}
		}
	}
	csv.Flush()

	return resp.String()
}

func GetAPIVoidReport(ctx context.Context, ioc string, APIvoidClient *http.Client, iocType triage.IOCType, APIVoidKey string) (*APIvoidReport, error) {
	var APIType string
	var APIParam string
	switch iocType {
	case triage.IPType:
		APIType = "iprep"
		APIParam = "ip"
	case triage.URLType:
		APIType = "urlrep"
		APIParam = "url"
	case triage.DomainType:
		APIType = "domainbl"
		APIParam = "host"
	default:
		return nil, fmt.Errorf("API Void report is canceled due to not supported IOC type: %s,%s", iocType, ioc)
	}
	URL := fmt.Sprintf(APIvoidEndpoint, APIType, APIParam, ioc, APIVoidKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, URL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := APIvoidClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad response status code: %d", resp.StatusCode)
	}

	reportHolder, err := ReformatResponse(resp.Body)
	// reportJSON, _ := json.Marshal(reportHolder)
	// reportURL, err := common.PutObjectInS3("apivoid.json", bytes.NewReader(reportJSON))
	// reportHolder.FullReportS3URL = reportURL
	return reportHolder, err
}

// ReformatResponse converts Object-like "engines" property to array as it supposed to be (probably bug in APIvoid)
func ReformatResponse(responseBody io.ReadCloser) (*APIvoidReport, error) {
	reportHolder := &APIvoidReport{}
	reportBody := ""
	b, err := io.ReadAll(responseBody)
	if err == nil {
		reportBody = string(b)
	} else {
		return nil, err
	}
	findEnginesGroup := regexp.MustCompile(`(?m)("engines":{)?("\d+":)({[^{}]*},?)(})?`)
	extractEnginesGroup := regexp.MustCompile(`(?m)(?:re"engines":{)?("\d+":)({[^{}]*})(?:re})?`)
	allEngines := extractEnginesGroup.FindAllStringSubmatch(reportBody, -1)
	reportBody = findEnginesGroup.ReplaceAllString(reportBody, "$1$4")
	allEnginesString := []string{}
	for _, engine := range allEngines {
		allEnginesString = append(allEnginesString, engine[2])
	}
	reportBody = strings.ReplaceAll(reportBody, `"engines":{}`, `"engines":[`+strings.Join(allEnginesString, ",")+`]`)

	err = json.Unmarshal([]byte(reportBody), reportHolder)
	if err != nil {
		return nil, err
	}
	return reportHolder, nil
}

//apiVoidMetaDataExtract gets the high level insights for APIVoidReport
func apiVoidMetaDataExtract(apivoidResults map[string]*APIvoidReport, iocType triage.IOCType) []string {
	var triageMetaData []string

	for ioc, data := range apivoidResults {
		triageMetaData = append(triageMetaData, fmt.Sprintf("IOC: %s, RiskScore:%v\n",
			ioc, data.Data.Report.RiskScore))
		triageMetaData = append(triageMetaData, fmt.Sprintf("IOC: %s, FullReportS3URL:%v\n",
			ioc, data.FullReportS3URL))
		if iocType == triage.IPType || iocType == triage.DomainType {
			engines := data.Data.Report.Blacklist
			triageMetaData = append(triageMetaData,
				fmt.Sprintf("IOC: %s,Detections:%d, Engines Count: %d, Detection Rate: %s\n", ioc, engines.Detections,
					engines.EnginesCount, engines.DetectionsRate))
			if iocType == triage.IPType {
				triageMetaData = append(triageMetaData, fmt.Sprintf("IOC: %s, Information:%v\n",
					ioc, data.Data.Report.Information))
				triageMetaData = append(triageMetaData, fmt.Sprintf("IOC: %s, Anonymity:%v\n",
					ioc, data.Data.Report.Anonymity))
			} else {
				triageMetaData = append(triageMetaData, fmt.Sprintf("IOC: %s, Server:%v\n",
					ioc, data.Data.Report.Server))
				triageMetaData = append(triageMetaData, fmt.Sprintf("IOC: %s, Category:%v\n",
					ioc, data.Data.Report.Category))
				triageMetaData = append(triageMetaData, fmt.Sprintf("IOC: %s, SecurityChecks:%v\n",
					ioc, data.Data.Report.SecurityChecks))
			}

		} else {
			engines := data.Data.Report
			triageMetaData = append(triageMetaData,
				fmt.Sprintf("IOC: %s,Detections:%d\n", ioc, engines.DomainBlacklist.Detections))
			triageMetaData = append(triageMetaData,
				fmt.Sprintf("IOC: %s,FileType:%v\n", ioc, engines.FileType))
			triageMetaData = append(triageMetaData,
				fmt.Sprintf("IOC: %s,GeoLocation:%v\n", ioc, engines.GeoLocation))
			triageMetaData = append(triageMetaData,
				fmt.Sprintf("IOC: %s,HTMLForms:%v\n", ioc, engines.HTMLForms))
			triageMetaData = append(triageMetaData,
				fmt.Sprintf("IOC: %s,Redirection:%v\n", ioc, engines.Redirection))
			triageMetaData = append(triageMetaData,
				fmt.Sprintf("IOC: %s,ResponseHeaders:%v\n", ioc, engines.ResponseHeaders))
			triageMetaData = append(triageMetaData, fmt.Sprintf("IOC: %s, SecurityChecks:%v\n",
				ioc, data.Data.Report.SecurityChecks))
			triageMetaData = append(triageMetaData, fmt.Sprintf("IOC: %s, ServerDetails:%v\n",
				ioc, data.Data.Report.ServerDetails))
			triageMetaData = append(triageMetaData, fmt.Sprintf("IOC: %s, SiteCategory:%v\n",
				ioc, data.Data.Report.SiteCategory))
			triageMetaData = append(triageMetaData, fmt.Sprintf("IOC: %s, URLParts:%v\n",
				ioc, data.Data.Report.URLParts))
			triageMetaData = append(triageMetaData, fmt.Sprintf("IOC: %s, WebPage:%v\n",
				ioc, data.Data.Report.WebPage))
		}

	}
	return triageMetaData
}
