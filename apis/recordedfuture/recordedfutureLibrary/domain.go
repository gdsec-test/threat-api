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
	domainEndpoint = "https://api.recordedfuture.com/v2/domain/"
)

// DomainReportFields are the fields to submit to get a standard domain report
var DomainReportFields = []string{"analystNotes", "counts", "enterpriseLists", "entity", "intelCard", "links", "metrics", "relatedEntities", "risk", "riskMapping", "sightings", "threatLists", "timestamps"}

// DomainReport is a sample report that recorded future returns when enriching a domain
// if you request the fields DomainReportFields
type DomainReport struct {
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
		IntelCard string        `json:"intelCard"`
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
		ThreatLists []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Type        string `json:"type"`
			Description string `json:"description"`
		} `json:"threatLists"`
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

// EnrichDomain  performs a CVE search with RecordedFuture
func EnrichDomain(ctx context.Context, RFKey string, RFClient *http.Client, ip string, fields []string, metadata bool) (*DomainReport, error) {
	// Build URL
	values := url.Values{}
	values.Add("fields", strings.Join(fields, ","))
	values.Add("metadata", fmt.Sprintf("%v", metadata))
	URL := fmt.Sprintf("%s%v?%s", domainEndpoint, ip, values.Encode())

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
		return nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	reportHolder := &DomainReport{}
	err = json.NewDecoder(resp.Body).Decode(reportHolder)
	if err != nil {
		return nil, err
	}

	return reportHolder, nil
}
