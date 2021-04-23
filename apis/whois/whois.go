package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/likexian/whois-go"
	whoisparser "github.com/likexian/whois-parser-go"
)

const (
	triageModuleName = "whois"
)

// WhoisStats contains some stats about the domains that have been looked up using whois
type WhoisStats struct {
	// The maps represent the name of the registrar or registrant paired to the whois results returned
	SameRegistrar  map[string][]*whoisparser.WhoisInfo
	SameRegistrant map[string][]*whoisparser.WhoisInfo
	InvalidDomains int
}

// Lookup performs a whoislookup on the passed in domains
func Lookup(ctx context.Context, domains []string) ([]*whoisparser.WhoisInfo, *WhoisStats) {
	stats := &WhoisStats{
		SameRegistrant: map[string][]*whoisparser.WhoisInfo{},
		SameRegistrar:  map[string][]*whoisparser.WhoisInfo{},
	}
	// Helper function to add an entry to our stats map
	addToMap := func(m map[string][]*whoisparser.WhoisInfo, key string, entry *whoisparser.WhoisInfo) {
		if _, ok := m[key]; ok {
			m[key] = append(m[key], entry)
			return
		}
		m[key] = []*whoisparser.WhoisInfo{entry}
	}

	// Get WhoisInfo
	whoisResults := []*whoisparser.WhoisInfo{}
	for _, domain := range domains {
		// Check context
		select {
		case <-ctx.Done():
			break
		default:
		}

		span, spanCtx := tb.TracerLogger.StartSpan(ctx, "WhoisLookup", "whois", "", "lookup")

		// AddErrRow is a standard to add an errored whois query to the list of results
		addErrRow := func(err error) {
			span.AddError(err)
			stats.InvalidDomains++
			whoisResults = append(whoisResults, &whoisparser.WhoisInfo{Domain: &whoisparser.Domain{Domain: domain}, Registrant: &whoisparser.Contact{}, Registrar: &whoisparser.Contact{Name: fmt.Sprintf("ERROR: %s", err)}, Administrative: &whoisparser.Contact{}})
		}

		// Convert to the base domain
		domainSplit := strings.Split(domain, ".")
		if len(domainSplit) < 2 {
			errString := fmt.Errorf("ioc passed is not a domain")
			addErrRow(errString)
			span.AddError(errString)
			span.End(spanCtx)
			continue
		}
		domain = fmt.Sprintf("%s.%s", domainSplit[len(domainSplit)-2], domainSplit[len(domainSplit)-1])

		// Look up domain
		// TODO: fix log
		// triage.Log(triageModuleName, "WhoisLookup", api, core.LogFields{"domain": domain})
		whoisRaw, err := whois.Whois(domain)
		if err != nil {
			span.AddError(err)
			addErrRow(err)
			span.End(spanCtx)
			continue
		}
		whoisResult, err := whoisparser.Parse(whoisRaw)
		if err != nil {
			span.AddError(err)
			addErrRow(err)
			span.End(spanCtx)
			continue
		}

		// Fill in with blank data if an element is missing
		if whoisResult.Registrant == nil {
			whoisResult.Registrant = &whoisparser.Contact{}
		}
		if whoisResult.Registrar == nil {
			whoisResult.Registrar = &whoisparser.Contact{}
		}
		if whoisResult.Administrative == nil {
			whoisResult.Administrative = &whoisparser.Contact{}
		}
		if whoisResult.Domain == nil {
			whoisResult.Domain = &whoisparser.Domain{}
		}

		// Add to stats and results
		addToMap(stats.SameRegistrant, whoisResult.Registrant.Name, &whoisResult)
		addToMap(stats.SameRegistrar, whoisResult.Registrar.Name, &whoisResult)
		whoisResults = append(whoisResults, &whoisResult)

		// Sleep a small time to avoid spamming their servers
		// TODO: Add token bucket for 1000 queries per day
		select {
		case <-ctx.Done():
			break
		case <-time.After(time.Millisecond * 500):
		}

		span.End(spanCtx)
	}

	return whoisResults, stats
}
