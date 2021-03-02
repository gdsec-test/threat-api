package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/opentracing/opentracing-go"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	ipEndpoint = "https://api.recordedfuture.com/v2/ip/"
)

//TODO: Check where this const should go ?
//IPReportFields are the fields to submit to get a standard IP report
var IPReportFields = []string{"analystNotes", "counts", "enterpriseLists", "entity", "intelCard", "location", "metrics", "relatedEntities", "risk", "riskyCIDRIPs", "sightings", "threatLists", "timestamps"}

// IPReport is a sample report that recorded future returns when enriching an IP
// if you request the fields IPReportFields
type IPReport struct {
	Data struct {
		RiskyCIDRIPs []struct {
			Score int `json:"score"`
			IP    struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"ip"`
		} `json:"riskyCIDRIPs"`
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
		Location        struct {
			Organization string `json:"organization"`
			Cidr         struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"cidr"`
			Location struct {
				Continent string `json:"continent"`
				Country   string `json:"country"`
				City      string `json:"city"`
			} `json:"location"`
			Asn string `json:"asn"`
		} `json:"location"`
		Timestamps struct {
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

//EnrichIP  performs a CVE search with RecordedFuture
func (m *TriageModule) EnrichIP(ctx context.Context, ip string, fields []string, metadata bool) (*IPReport, error) {
	// Build URL
	values := url.Values{}
	values.Add("fields", strings.Join(fields, ","))
	values.Add("metadata", fmt.Sprintf("%v", metadata))
	URL := fmt.Sprintf("%s%v?%s", ipEndpoint, ip, values.Encode())

	// Build request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, URL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("X-RFToken", m.RFKey)

	var IPspan opentracing.Span
	IPspan, ctx = opentracing.StartSpanFromContext(ctx, "EnrichIP")
	defer IPspan.Finish()

	resp, err := m.RFClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	reportHolder := &IPReport{}
	err = json.NewDecoder(resp.Body).Decode(reportHolder)
	if err != nil {
		return nil, err
	}

	return reportHolder, nil
}
