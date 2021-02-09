package main

import (
	"context"
	"net"

	"github.com/ns3777k/go-shodan/v4/shodan"
)

const (
	triageModuleName = "whois"
)

// Host is a structure to store what we found from shodan along with other information about that host
type Host struct {
	Domain     string
	ShodanHost *shodan.Host
}

// GetServicesForIPs Gets shodan host information for a list of IPs
func (m *TriageModule) GetServicesForIPs(ctx context.Context, ips map[string]*net.IP) []*Host {
	//TODO: Add tokenbuckets
	hosts := []*Host{}

	// Enrich all ips
	for domain, ip := range ips {
		// Check context
		select {
		case <-ctx.Done():
			break
		default:
		}

		host, err := m.shodanClient.GetServicesForHost(ctx, ip.String(), &shodan.HostServicesOptions{})
		if err != nil {
			continue
		}
		hosts = append(hosts, &Host{Domain: domain, ShodanHost: host})
	}

	return hosts
}
