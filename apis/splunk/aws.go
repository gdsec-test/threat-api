package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
	"github.com/vertoforce/go-splunk"
)

const (
	// TODO: instead find all recent events with this hostname, instead of just one item
	awsHostnameSearch = `index=*aws_config earliest=-1d  "configuration.privateDnsName"="%s" | dedup ARN | head 1 | table host product configuration.privateIpAddress configuration.association.publicIp awsRegion awsAccountId`
)

// triageAWSHostnames Finds information on AWS machines
func (m *TriageModule) triageAWSHostnames(ctx context.Context, triageRequest *triage.Request) []*triage.Data {
	triageData := &triage.Data{
		Title:    "Splunk machine information",
		Metadata: []string{},
	}
	wg := sync.WaitGroup{}                                    // Wait group for our running threads
	metadataLock := sync.Mutex{}                              // Lock access to the metadata slice
	threadLimit := make(chan int, maxConcurnetSplunkSearches) // Use a buffered channel to limit the amount of threads we spawn

	// Start a multithreaded operation performing splunk searches (with a max thread limit)
	// And getting the results
	for _, hostname := range triageRequest.IOCs {
		// Consume thread
		threadLimit <- 1
		wg.Add(1)
		go func(hostname string) {
			span, _ := tb.TracerLogger.StartSpan(ctx, "SplunkScanAWSHostname", "splunk.aws.search")
			defer span.End(ctx)

			search, err := m.splunkClient.CreateSearchJob(ctx, fmt.Sprintf(awsHostnameSearch, hostname), map[string]string{
				"earliest_time": splunk.FormatTime(time.Now().Add(-time.Hour * 24 * recentLoginsBackcheckDays)),
			})
			if err != nil {
				span.AddError(err)
				return
			}
			results, err := search.GetResults(ctx)
			if err != nil {
				span.AddError(err)
				return
			}
			for result := range results {
				metadataLock.Lock()
				triageData.Metadata = append(triageData.Metadata, fmt.Sprintf(
					"*%s* was found <%s|associated with an AWS item>.  AWS Account ID: *%s* Host: *%s* Product: *%s* Private IP: *%s* Public IP: *%s* AWS Region: *%s*",
					hostname,
					search.URL(),
					result.GetFieldString("awsAccountId"),
					result.GetFieldString("host"),
					result.GetFieldString("product"),
					result.GetFieldString("configuration.privateIpAddress"),
					result.GetFieldString("configuration.association.publicIp"),
					result.GetFieldString("awsRegion"),
				))
				metadataLock.Unlock()
			}
			<-threadLimit
			wg.Done()
		}(hostname)
	}
	wg.Wait()

	return []*triage.Data{triageData}
}
