package main

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/vertoforce/go-splunk"
)

func (m *TriageModule) initClient(ctx context.Context) error {
	// Check if we already set up the client
	if m.splunkClient != nil {
		return nil
	}

	// Parse the splunk certificate chain PEM block
	splunkCertChain := tls.Certificate{}
	var certDERBlock *pem.Block
	certPEMBlock := []byte(splunkDefaultCertChainRaw)
	for {
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			splunkCertChain.Certificate = append(splunkCertChain.Certificate, certDERBlock.Bytes)
		}
	}
	// Build TLS config, adding x509 certificates
	tlsConfig := &tls.Config{}
	tlsConfig.RootCAs = x509.NewCertPool()
	for _, cert := range splunkCertChain.Certificate {
		x509Cert, err := x509.ParseCertificate(cert)
		if err != nil {
			return fmt.Errorf("bad splunk certificate")
		}
		x509Cert.Subject.Names = append(x509Cert.Subject.Names, pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "godaddy.splunkcloud.com"})
		x509Cert.Subject.CommonName = ""
		fmt.Printf("%s", x509Cert.Subject.Names)
		tlsConfig.RootCAs.AddCert(x509Cert)
	}
	tlsConfig.ServerName = "SplunkServerDefaultCert"
	tlsConfig.RootCAs.AppendCertsFromPEM([]byte(splunkDefaultCertChainRaw))
	tlsConfig.BuildNameToCertificate()

	client, err := splunk.NewClient(ctx, m.SplunkUsername, m.SplunkPassword, &splunk.Config{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					// TODO: Change this to accept the cert instead
					InsecureSkipVerify: true,
				},
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
