package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	ipEndpoint = "https://api.recordedfuture.com/v2/ip/"
)

//TODO: Code breaks for more than 1 IP (Given the tests example IP's )

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
	req, err := http.NewRequestWithContext(ctx, "GET", URL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("X-RFToken", m.RFKey)
	resp, err := m.RFClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	reportHolder := &IPReport{}
	err = json.NewDecoder(resp.Body).Decode(reportHolder)
	if err != nil {
		return nil, err
	}

	return reportHolder, nil
}

//ipMetaDataExtract gets the high level insights for IP
func ipMetaDataExtract(rfIPResults map[string]*IPReport) []string {
	var triageMetaData []string
	intelCardLinks := make(map[string]string)
	riskyCIDRIPs := make(map[string]int)

	riskIP := 0

	for ip, data := range rfIPResults {
		// Add the RF Intelligence Card link to every IP for easy access to people with RF UI access
		if data.Data.IntelCard != "" {
			intelCardLinks[ip] = data.Data.IntelCard
		}

		// Keep the count of risky CIDR IP
		if len(data.Data.RiskyCIDRIPs) > 0 {
			riskyCIDRIPs[ip] = len(data.Data.RiskyCIDRIPs)
		}

		// Calculate on risk score
		if data.Data.Risk.Score > 60 {
			riskIP += 1
		}
	}

	// Add the final results to Metadata
	if len(intelCardLinks) > 0 {
		for ip, link := range intelCardLinks {
			triageMetaData = append(triageMetaData, fmt.Sprintf("RF Link for %s: %s", ip, link))
		}
	}

	if len(riskyCIDRIPs) > 0 {
		for ip, count := range riskyCIDRIPs {
			triageMetaData = append(triageMetaData, fmt.Sprintf("%d Risky IP's in same CIDR as %s", count, ip))
		}
	}

	if riskIP > 0 {
		triageMetaData = append(triageMetaData, fmt.Sprintf("%d IP's have a risk score > 60", riskIP))
	}
	return triageMetaData
}

//dumpIPCSV dumps the triage data to CSV
func dumpIPCSV(rfIPResults map[string]*IPReport) string {
	//Dump data as csv
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	csv.Write([]string{
		"IntelCardLink",
		"Risk Score",
		"Criticality",
		"CriticalityLabel",
		"First Seen",
		"Last Seen",
		"ThreatLists",
		// TODO: Evidence Details- show it in a better way
		//TODO: "Analyst Notes- a better way to display",
	})
	for _, data := range rfIPResults {
		// Processing few non string data before adding to CSV
		var threatLists []string
		for _, threatlist := range data.Data.ThreatLists {
			threatLists = append(threatLists, threatlist.Name)
		}

		cols := []string{
			data.Data.IntelCard,
			fmt.Sprintf("%d", data.Data.Risk.Score),
			fmt.Sprintf("%d", data.Data.Risk.Criticality),
			data.Data.Risk.CriticalityLabel,
			data.Data.Timestamps.FirstSeen.String(),
			data.Data.Timestamps.LastSeen.String(),
			strings.Join(threatLists, " "),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}
