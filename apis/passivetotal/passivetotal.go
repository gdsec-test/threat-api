package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"strings"
	"sync"

	pt "github.com/gdcorp-infosec/threat-api/apis/passivetotal/passivetotalLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	maxThreadCount = 5
)

func (m *TriageModule) GetPassiveDNS(ctx context.Context, triageRequest *triage.Request) (map[string]*pt.PDNSReport, error) {

	ptDNSResults := make(map[string]*pt.PDNSReport)

	wg := sync.WaitGroup{}
	pdnsLock := sync.Mutex{}
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

		span, spanCtx := tb.TracerLogger.StartSpan(ctx, "PassiveDNSLookup", "passivetotal", "", "passiveDNSLookup")

		go func(ioc string) {
			defer func() {
				<-threadLimit
				wg.Done()
			}()

			pdnsResult, err := pt.GetPassiveDNS(ctx, passiveDNSURL, ioc, m.PTUser, m.PTKey, m.PTClient)
			if err != nil {
				span.AddError(err)
				pdnsLock.Lock()
				ptDNSResults[ioc] = nil
				pdnsLock.Unlock()
				return
			}

			pdnsLock.Lock()
			ptDNSResults[ioc] = pdnsResult
			pdnsLock.Unlock()
		}(ioc)
		span.End(spanCtx)
	}

	wg.Wait()
	return ptDNSResults, nil
}

func (m *TriageModule) GetUniquePassiveDNS(ctx context.Context, triageRequest *triage.Request) (map[string]*pt.PDNSUniqueReport, error) {

	ptDNSUniqueResults := make(map[string]*pt.PDNSUniqueReport)

	wg := sync.WaitGroup{}
	pdnsLock := sync.Mutex{}
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

		span, spanCtx := tb.TracerLogger.StartSpan(ctx, "PassiveDNSUniqueLookup", "passivetotal", "", "passiveDNSuniqueLookup")

		go func(ioc string) {
			defer func() {
				<-threadLimit
				wg.Done()
			}()

			pdnsUniqueResult, err := pt.GetUniquePassiveDNS(ctx, passiveDNSURL, ioc, m.PTUser, m.PTKey, m.PTClient)

			if err != nil {
				span.AddError(err)
				pdnsLock.Lock()
				ptDNSUniqueResults[ioc] = nil
				pdnsLock.Unlock()
				return
			}

			pdnsLock.Lock()
			ptDNSUniqueResults[ioc] = pdnsUniqueResult
			pdnsLock.Unlock()
		}(ioc)
		span.End(spanCtx)
	}

	wg.Wait()
	return ptDNSUniqueResults, nil
}

//dumpPDNSCSV dumps the passiveDNS triage data to CSV
func dumpPDNSCSV(ptPDNSResults map[string]*pt.PDNSReport) string {
	//Dump data as csv
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	csv.Write([]string{
		"Domain/IP",
		"FirstSeen",
		"ResolveType",
		"Value",
		"RecordHash",
		"LastSeen",
		"Resolve",
		"Source",
		"RecordType",
		"Collected",
	})
	for ioc, data := range ptPDNSResults {
		if data == nil {
			continue
		}

		for _, result := range data.Results {
			cols := []string{
				ioc,
				result.FirstSeen,
				result.ResolveType,
				result.Value,
				result.RecordHash,
				result.LastSeen,
				result.Resolve,
				strings.Join(result.Source, " "),
				result.RecordType,
				result.Collected,
			}
			csv.Write(cols)
		}
	}
	csv.Flush()

	return resp.String()
}

//dumpPDNSCSV dumps the passiveDNS triage data to CSV
func dumpUniquePDNSCSV(ptPDNSUniqueResults map[string]*pt.PDNSUniqueReport) string {
	//Dump data as csv
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	csv.Write([]string{
		"Domain/IP",
		"Result",
		"Frequency",
	})
	for ioc, data := range ptPDNSUniqueResults {
		if data == nil {
			continue
		}

		for _, result := range data.Frequency {
			cols := []string{
				ioc,
				fmt.Sprintf("%v", result[0]),
				fmt.Sprintf("%v", result[1]),
			}
			csv.Write(cols)
		}
	}
	csv.Flush()

	return resp.String()
}
