package recordedfutureLibrary

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	urlEndpoint = "https://api.recordedfuture.com/v2/url/"
)

// UrlReportFields are the fields to submit to get a standard URL report
var UrlReportFields = []string{"analystNotes", "counts", "enterpriseLists", "entity", "links", "metrics", "relatedEntities", "risk", "riskMapping", "sightings", "timestamps"}

// UrlReport is a sample report that recorded future returns when enriching a URL
// if you request the fields UrlReportFields
type UrlReport struct {
	Data struct {
		EnterpriseLists []interface{} `json:"enterpriseLists"`
		Risk            struct {
			CriticalityLabel string `json:"criticalityLabel"`
			RiskString       string `json:"riskString"`
			Rules            int    `json:"rules"`
			Criticality      int    `json:"criticality"`
			RiskSummary      string `json:"riskSummary"`
			Score            int    `json:"score"`
			EvidenceDetails  []struct {
				MitigationString string    `json:"mitigationString"`
				EvidenceString   string    `json:"evidenceString"`
				Rule             string    `json:"rule"`
				Criticality      int       `json:"criticality"`
				Timestamp        time.Time `json:"timestamp"`
				CriticalityLabel string    `json:"criticalityLabel"`
			} `json:"evidenceDetails"`
		} `json:"risk"`
		Sightings []interface{} `json:"sightings"`
		Entity    struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"entity"`
		RelatedEntities []interface{} `json:"relatedEntities"`
		AnalystNotes    []interface{} `json:"analystNotes"`
		Timestamps      struct {
			LastSeen  time.Time `json:"lastSeen"`
			FirstSeen time.Time `json:"firstSeen"`
		} `json:"timestamps"`
		Counts  []interface{} `json:"counts"`
		Metrics []struct {
			Type  string `json:"type"`
			Value int    `json:"value"`
		} `json:"metrics"`
		Links struct {
			Error string `json:"error"`
		} `json:"links"`
		RiskMapping []struct {
			Rule       string `json:"rule"`
			Categories []struct {
				Framework string `json:"framework"`
				Name      string `json:"name"`
			} `json:"categories"`
		} `json:"riskMapping"`
	} `json:"data"`
	Metadata struct {
		Entries []struct {
			Key   string `json:"key"`
			Label string `json:"label"`
			Item  struct {
				Entries []struct {
					Key     string `json:"key"`
					Label   string `json:"label,omitempty"`
					Type    string `json:"type"`
					Entries []struct {
						Key   string `json:"key"`
						Label string `json:"label"`
						Type  string `json:"type"`
						Item  struct {
							Type string `json:"type"`
						} `json:"item,omitempty"`
						Required bool `json:"required,omitempty"`
					} `json:"entries,omitempty"`
				} `json:"entries"`
				Type string `json:"type"`
			} `json:"item,omitempty"`
			Type    string `json:"type"`
			Entries []struct {
				Key     string `json:"key"`
				Label   string `json:"label"`
				Type    string `json:"type"`
				Entries []struct {
					Key   string `json:"key"`
					Label string `json:"label"`
					Type  string `json:"type"`
				} `json:"entries,omitempty"`
			} `json:"entries,omitempty"`
		} `json:"entries"`
	} `json:"metadata"`
}

// EnrichUrl  performs a CVE search with RecordedFuture
func EnrichUrl(ctx context.Context, RFKey string, RFClient *http.Client, ioc string, fields []string, metadata bool) (*UrlReport, error) {
	// Build URL
	values := url.Values{}
	values.Add("fields", strings.Join(fields, ","))
	values.Add("metadata", fmt.Sprintf("%v", metadata))
	URL := fmt.Sprintf("%s%s?%s", urlEndpoint, url.QueryEscape(ioc), values.Encode())

	// Build request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, URL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("X-RFToken", RFKey)

	resp, err := RFClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Bad response status code: %d", resp.StatusCode)
	}

	reportHolder := &UrlReport{}
	err = json.NewDecoder(resp.Body).Decode(reportHolder)
	if err != nil {
		return nil, err
	}

	return reportHolder, nil
}
