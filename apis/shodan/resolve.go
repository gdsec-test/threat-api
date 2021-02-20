package main

import (
	"context"
	"net"
	"time"
)

const (
	// max time to spend per dns lookup
	maxLookupTime = time.Second * 5
)

// resolveDomains resolves the domains to IPs using shodan
func (m *TriageModule) resolveDomains(ctx context.Context, domains []string) map[string]*net.IP {
	ctxLookup, cancel := context.WithTimeout(ctx, maxLookupTime)
	defer cancel()
	ipsResolved, err := m.shodanClient.GetDNSResolve(ctxLookup, domains)
	if err != nil {
		return nil
	}

	return ipsResolved
}
