package main

import (
	"context"
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
