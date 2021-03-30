package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"github.com/vertoforce/go-splunk"
)

func (m *TriageModule) initClient(ctx context.Context) error {
	// Check if we already set up the client
	if m.splunkClient != nil {
		return nil
	}

	// Parse the splunk certificate chain PEM block
	tlsConfig := &tls.Config{}
	tlsConfig.RootCAs = x509.NewCertPool()
	tlsConfig.RootCAs.AppendCertsFromPEM([]byte(splunkDefaultCertChainRaw))
	tlsConfig.ServerName = "SplunkServerDefaultCert"

	client, err := splunk.NewClient(ctx, m.SplunkUsername, m.SplunkPassword, &splunk.Config{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
		BaseURL: m.SplunkBaseURL,
	})
	if err != nil {
		return err
	}

	m.splunkClient = client

	return nil
}
