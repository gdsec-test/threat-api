package passivetotalLibrary

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

const (
	PassiveDNSPath = "/v2/dns/passive"
)

type PDNSReportResult struct {
	FirstSeen   string   `json:"firstSeen"`
	ResolveType string   `json:"resolveType"`
	Value       string   `json:"value"`
	RecordHash  string   `json:"recordHash"`
	LastSeen    string   `json:"lastSeen"`
	Resolve     string   `json:"resolve"`
	Source      []string `json:"source"`
	RecordType  string   `json:"recordType"`
	Collected   string   `json:"collected"`
}

type PDNSReport struct {
	TotalRecords int                `json:"totalRecords"`
	FirstSeen    string             `json:"firstSeen"`
	LastSeen     string             `json:"lastSeen"`
	Results      []PDNSReportResult `json:"results"`
	QueryType    string             `json:"queryType"`
	Pager        interface{}        `json:"pager"`
	QueryValue   string             `json:"queryValue"`
}

type PassiveTotalResolution struct {
	Value     string   `json:"ip"`
	FirstSeen string   `json:"firstSeen"`
	LastSeen  string   `json:"lastSeen"`
	Sources   []string `json:"sources"`
}

type PassiveTotalResponse struct {
	Value       string                   `json:"domain"`
	FirstSeen   string                   `json:"firstSeen"`
	LastSeen    string                   `json:"lastSeen"`
	Resolutions []PassiveTotalResolution `json:"resolutions"`
}

// Convert the structure returned by Passive Total into the
// structure that the API will return
func (p *PDNSReport) MakeDomainResponse() *PassiveTotalResponse {
	response := PassiveTotalResponse{
		Value:     p.QueryValue,
		FirstSeen: p.FirstSeen,
		LastSeen:  p.LastSeen,
	}
	for _, q := range p.Results {
		response.Resolutions = append(response.Resolutions, *q.MakeDomainResolution())
	}
	return &response
}

// Convert the nested structure returned by Passive Total into the
// structure that the API will return
func (p *PDNSReportResult) MakeDomainResolution() *PassiveTotalResolution {
	return &PassiveTotalResolution{
		Value:     p.Resolve,
		FirstSeen: p.FirstSeen,
		LastSeen:  p.LastSeen,
		Sources:   p.Source,
	}
}

func GetPassiveDNS(ctx context.Context, ptUrl string, ioc string, user string, key string, PTClient *http.Client) (*PDNSReport, error) {
	// Build URL
	values := url.Values{}
	values.Add("query", ioc)
	URL := fmt.Sprintf("%s%s?%s", ptUrl, PassiveDNSPath, values.Encode())

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
