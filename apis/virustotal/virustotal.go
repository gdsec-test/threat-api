package main

import (
	"context"
	"crypto/sha256"
	"fmt"

	vt "github.com/VirusTotal/vt-go"
)

const (
	triageModuleName = "virustotal"
	hashPath         = "files/%s"
	urlPath          = "urls/%s"
	domainPath       = "domains/%s"
	ipPath           = "ip_addresses/%s"
)

type VirusTotal struct {
	apiKey string
	client *vt.Client
}

func NewVirusTotal(apiKey string) *VirusTotal {
	virusTotal := new(VirusTotal)
	virusTotal.apiKey = apiKey
	virusTotal.client = vt.NewClient(apiKey)
	return virusTotal
}

func (m *VirusTotal) GetHash(ctx context.Context, hash string) (*vt.Object, error) {
	url := vt.URL(hashPath, hash)
	obj, err := m.client.GetObject(url)
	if err != nil {
		return nil, err
	}
	return obj, nil
}

func (m *VirusTotal) GetURL(ctx context.Context, _url string) (*vt.Object, error) {
	hashedUrl := sha256.Sum256([]byte(_url))
	stringHashedUrl := fmt.Sprintf("%x", hashedUrl[:])
	url := vt.URL(urlPath, stringHashedUrl)
	obj, err := m.client.GetObject(url)
	if err != nil {
		return nil, err
	}
	return obj, nil
}

func (m *VirusTotal) GetDomain(ctx context.Context, domain string) (*vt.Object, error) {
	url := vt.URL(domainPath, domain)
	obj, err := m.client.GetObject(url)
	if err != nil {
		return nil, err
	}
	return obj, nil
}

func (m *VirusTotal) GetAddress(ctx context.Context, ip string) (*vt.Object, error) {
	url := vt.URL(ipPath, ip)
	obj, err := m.client.GetObject(url)
	if err != nil {
		return nil, err
	}
	return obj, nil
}
