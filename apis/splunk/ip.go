package main

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	// onPremLogginEvents are any event on prem regarding login to some host
	onPremLoginEvent = `index=on_prem tag=authentication (message="Failed password*" OR message="Invalid user*") message="*%s*"
	| rex field=message "\b(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
	| table message _time product host src_ip
	| stats count by product src_ip`
	// Okta logins from IP
	recentOktaLoginsByIPSearch = `index=oktalogs src_ip="%s" displayMessage="User single sign on to app" | stats count by src_ip user`
	// Search for any on_prem log mentioning the IP
	// TODO: Fis this to not match ips with suffixes / prefixes on the provided ips
	eventWithIP = `index=on_prem "*%s*" | rex field=_raw "\b(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b" | stats count`
	// AWS config item search
	awsConfigItemSearch = `index=*aws_config earliest=-1d resourceType="AWS::EC2::NetworkInterface" ("configuration.association.publicIp"="%s" OR "configuration.privateIpAddress"="%s") | fields host product configuration.privateIpAddress configuration.association.publicIp awsRegion awsAccountId`

	// Limits
	maxSplunkWaitTime          = time.Second * 30
	maxConcurnetSplunkSearches = 5
)

// triageIPs Finds failed login attempts and other events mentioning the ips.
// It does not return any real data, instead linking to splunk searches
func (m *TriageModule) triageIPs(ctx context.Context, triageRequest *triage.Request) []*triage.Data {
	triageData := &triage.Data{
		Title:    "Splunk IP Events",
		Metadata: []string{},
	}
	wg := sync.WaitGroup{}                                    // Wait group for our running threads
	metadataLock := sync.Mutex{}                              // Lock access to the metadata slice
	threadLimit := make(chan int, maxConcurnetSplunkSearches) // Use a buffered channel to limit the amount of threads we spawn

	// Start a multithreaded operation performing splunk searches (with a max thread limit)
	// And getting the results
ipLoop:
	for _, ip := range triageRequest.IOCs {
		// Search for on prem failed login events
		select {
		case <-ctx.Done():
			break ipLoop
		case threadLimit <- 1:
			wg.Add(1)
		}
		go func(ip string) {
			defer func() {
				<-threadLimit
				wg.Done()
			}()
			results, search, err := m.performSplunkSearch(ctx, fmt.Sprintf(onPremLoginEvent, ip))
			if err != nil {
				return
			}
			for result := range results {
				if result["count"] == "0" {
					continue
				}
				metadataLock.Lock()
				triageData.Metadata = append(triageData.Metadata, fmt.Sprintf("*%s* had >=*%s* <%s|failed on prem logins> to *%s* in the last *%d* days", ip, result["count"], search.URL(), result["product"], recentLoginsBackcheckDays))
				metadataLock.Unlock()
			}
		}(ip)

		// Search for any generic IP events
		select {
		case <-ctx.Done():
			break ipLoop
		case threadLimit <- 1:
			wg.Add(1)
		}
		go func(ip string) {
			defer func() {
				<-threadLimit
				wg.Done()
			}()
			results, search, err := m.performSplunkSearch(ctx, fmt.Sprintf(eventWithIP, ip))
			if err != nil {
				return
			}
			for result := range results {
				if result["count"] == "0" {
					continue
				}
				metadataLock.Lock()
				triageData.Metadata = append(triageData.Metadata, fmt.Sprintf("*%s* was found in >=*%s* <%s|events in splunk> in the last *%d* days", ip, result["count"], search.URL(), recentLoginsBackcheckDays))
				metadataLock.Unlock()
			}
		}(ip)

		// Search for okta logins from IP
		select {
		case <-ctx.Done():
			break ipLoop
		case threadLimit <- 1:
			wg.Add(1)
		}
		go func(ip string) {
			defer func() {
				<-threadLimit
				wg.Done()
			}()
			results, search, err := m.performSplunkSearch(ctx, fmt.Sprintf(recentOktaLoginsByIPSearch, ip))
			if err != nil {
				return
			}
			userCount := 0
			loginCount := uint64(0)
			for result := range results {
				userCount++
				userLoginCount, _ := strconv.ParseUint(result.GetFieldString("count"), 10, 64)
				loginCount += userLoginCount
			}
			if userCount > 0 || loginCount > 0 {
				metadataLock.Lock()
				triageData.Metadata = append(triageData.Metadata,
					fmt.Sprintf("*%s* had >=*%d* <%s|okta logins> from >=*%d* unique users in the last *%d* days",
						ip,
						loginCount,
						search.URL(),
						userCount,
						recentLoginsBackcheckDays,
					))
				metadataLock.Unlock()
			}
		}(ip)

		// Search for AWS item
		select {
		case <-ctx.Done():
			break ipLoop
		case threadLimit <- 1:
			wg.Add(1)
		}
		go func(ip string) {
			defer func() {
				<-threadLimit
				wg.Done()
			}()
			results, search, err := m.performSplunkSearch(ctx, fmt.Sprintf(awsConfigItemSearch, ip, ip))
			if err != nil {
				return
			}
			for result := range results {
				metadataLock.Lock()
				triageData.Metadata = append(triageData.Metadata, fmt.Sprintf(
					"*%s* was found <%s|associated with an AWS item>.  AWS Account ID: *%s* Host: *%s* Product: *%s* Private IP: *%s* Public IP: *%s* AWS Region: *%s*",
					ip,
					search.URL(),
					result["awsAccountId"],
					result["host"],
					result["product"],
					result["configuration.privateIpAddress"],
					result["configuration.association.publicIp"],
					result["awsRegion"],
				))
				metadataLock.Unlock()
			}
		}(ip)
	}
	wg.Wait()

	return []*triage.Data{triageData}
}
