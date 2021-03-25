package main

import (
	"context"
	"encoding/json"

	vt "github.com/VirusTotal/vt-go"
)

const (
	triageModuleName = "virustotal"
	hashPath = "files/%s"
	urlPath = "urls/%s"
	domainHash = "domains/%s"
	ipHash = "ip_addresses/%s"
)

type VirusModule struct {
	apiKey string
}

func (m *VirusModule) GetHash(ctx context.Context, hash string) (*vt.Object, error) {
	// TODO: use context object

	// TODO: move into constructor?
	client := vt.NewClient(m.apiKey)

	data, err := client.GetObject(vt.URL("hahes/%s/analyses", hash))
	if err != nil {
		return nil, err
	}

	return data, nil
}
