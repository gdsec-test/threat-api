package passivetotalLibrary

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

const (
	passiveDNSEndpoint = "https://api.passivetotal.org/v2/dns/passive"
)

type PDNSReport struct {
	TotalRecords int    `json:"totalRecords"`
	FirstSeen    string `json:"firstSeen"`
	LastSeen     string `json:"lastSeen"`
	Results      []struct {
		FirstSeen   string   `json:"firstSeen"`
		ResolveType string   `json:"resolveType"`
		Value       string   `json:"value"`
		RecordHash  string   `json:"recordHash"`
		LastSeen    string   `json:"lastSeen"`
		Resolve     string   `json:"resolve"`
		Source      []string `json:"source"`
		RecordType  string   `json:"recordType"`
		Collected   string   `json:"collected"`
	} `json:"results"`
	QueryType  string      `json:"queryType"`
	Pager      interface{} `json:"pager"`
	QueryValue string      `json:"queryValue"`
}

type PDNSUniqueReport struct {
	Pager      interface{}     `json:"pager"`
	Frequency  [][]interface{} `json:"frequency"`
	Total      int             `json:"total"`
	QueryValue string          `json:"queryValue"`
	Results    []string        `json:"results"`
	QueryType  string          `json:"queryType"`
}

func GetPassiveDNS(ctx context.Context, ioc string, user string, key string, PTClient *http.Client) (*PDNSReport, error) {
	// Build URL
	values := url.Values{}
	values.Add("query", ioc)
	URL := fmt.Sprintf("%s?%s", passiveDNSEndpoint, values.Encode())
	fmt.Println(URL)

	// Build request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, URL, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(user, key)

	resp, err := PTClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	reportHolder := &PDNSReport{}
	err = json.NewDecoder(resp.Body).Decode(reportHolder)
	if err != nil {
		return nil, err
	}

	return reportHolder, nil
}

//EnrichCVE  performs a CVE search with RecordedFuture
func GetUniquePassiveDNS(ctx context.Context, ioc string, user string, key string, PTClient *http.Client) (*PDNSUniqueReport, error) {
	// TODO: When the rate limits are high, this can be calculated by ourself by processing the above results
	// Build URL
	values := url.Values{}
	values.Add("query", ioc)
	URL := fmt.Sprintf("%s%s?%s", passiveDNSEndpoint, "/unique", values.Encode())
	fmt.Println(URL)

	// Build request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, URL, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(user, key)

	resp, err := PTClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	reportHolder := &PDNSUniqueReport{}
	err = json.NewDecoder(resp.Body).Decode(reportHolder)
	if err != nil {
		return nil, err
	}

	return reportHolder, nil
}
