package exampleLibrary

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

const (
	// TODO: Add endpoints as offered by your service API
	egEndpoint = ""
)

type EgReport struct {
}

// GetExampleIoCEnrich TODO: Add description
func GetExampleIoCEnrich(ctx context.Context, ioc string, user string, key string, EgClient *http.Client) (*EgReport, error) {
	// Build URL
	values := url.Values{}
	values.Add("query", ioc) // TODO: Add anymore key value pairs for query to build URL
	URL := fmt.Sprintf("%s?%s", egEndpoint, values.Encode())

	// Build request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, URL, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(user, key)

	resp, err := EgClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	reportHolder := &EgReport{}
	err = json.NewDecoder(resp.Body).Decode(reportHolder)
	if err != nil {
		return nil, err
	}

	return reportHolder, nil
}
