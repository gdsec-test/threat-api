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
	triageModuleName      = "recordedfuture"
	vulnerabilityEndpoint = "https://api.recordedfuture.com/v2/vulnerability/"
)

// CVEReport is a sample report that recorded future returns when enriching a CVE
// if you request the fields CVEReportFields
type CVEReport struct {
	Data struct {
		RelatedLinks []string `json:"relatedLinks"`
		AnalystNotes []struct {
			Source struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"source"`
			Attributes struct {
				ValidatedOn time.Time `json:"validated_on"`
				Tlp         string    `json:"tlp"`
				Published   time.Time `json:"published"`
				Text        string    `json:"text"`
				Topic       struct {
					ID   string `json:"id"`
					Name string `json:"name"`
					Type string `json:"type"`
				} `json:"topic"`
				Title        string `json:"title"`
				NoteEntities []struct {
					ID          string `json:"id"`
					Name        string `json:"name"`
					Type        string `json:"type"`
					Description string `json:"description,omitempty"`
				} `json:"note_entities"`
				ContextEntities []struct {
					ID          string `json:"id"`
					Name        string `json:"name"`
					Type        string `json:"type"`
					Description string `json:"description,omitempty"`
				} `json:"context_entities"`
				ValidationUrls []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
					Type string `json:"type"`
				} `json:"validation_urls"`
			} `json:"attributes,omitempty"`
			ID string `json:"id"`
		} `json:"analystNotes"`
		EnterpriseLists []interface{} `json:"enterpriseLists"`
		Timestamps      struct {
			FirstSeen time.Time `json:"firstSeen"`
			LastSeen  time.Time `json:"lastSeen"`
		} `json:"timestamps"`
		ThreatLists []interface{} `json:"threatLists"`
		Risk        struct {
			CriticalityLabel string `json:"criticalityLabel"`
			Score            int    `json:"score"`
			EvidenceDetails  []struct {
				MitigationString interface{} `json:"mitigationString"`
				Timestamp        time.Time   `json:"timestamp"`
				CriticalityLabel string      `json:"criticalityLabel"`
				EvidenceString   string      `json:"evidenceString"`
				Rule             string      `json:"rule"`
				Criticality      int         `json:"criticality"`
			} `json:"evidenceDetails"`
			RiskString  string `json:"riskString"`
			Rules       int    `json:"rules"`
			Criticality int    `json:"criticality"`
			RiskSummary string `json:"riskSummary"`
		} `json:"risk"`
		CommonNames []string `json:"commonNames"`
		Cvssv3      struct {
		} `json:"cvssv3"`
		IntelCard string `json:"intelCard"`
		Rawrisk   []struct {
			Rule      string    `json:"rule"`
			Timestamp time.Time `json:"timestamp"`
		} `json:"rawrisk"`
		Cpe22URI  []string `json:"cpe22uri"`
		Sightings []struct {
			Source    string    `json:"source"`
			URL       string    `json:"url"`
			Published time.Time `json:"published"`
			Fragment  string    `json:"fragment"`
			Title     string    `json:"title"`
			Type      string    `json:"type"`
		} `json:"sightings"`
		Entity struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Type        string `json:"type"`
			Description string `json:"description"`
		} `json:"entity"`
		Counts []struct {
			Count int    `json:"count"`
			Date  string `json:"date"`
		} `json:"counts"`
		Metrics []struct {
			Type  string  `json:"type"`
			Value float64 `json:"value"`
		} `json:"metrics"`
		Cpe             []string `json:"cpe"`
		RelatedEntities []struct {
			Type     string `json:"type"`
			Entities []struct {
				Count  int `json:"count"`
				Entity struct {
					ID   string `json:"id"`
					Name string `json:"name"`
					Type string `json:"type"`
				} `json:"entity"`
			} `json:"entities"`
		} `json:"relatedEntities"`
		NvdDescription string `json:"nvdDescription"`
		Cvss           struct {
			AccessVector     string    `json:"accessVector"`
			LastModified     time.Time `json:"lastModified"`
			Published        time.Time `json:"published"`
			Score            float64   `json:"score"`
			Availability     string    `json:"availability"`
			Confidentiality  string    `json:"confidentiality"`
			Version          string    `json:"version"`
			Authentication   string    `json:"authentication"`
			AccessComplexity string    `json:"accessComplexity"`
			Integrity        string    `json:"integrity"`
		} `json:"cvss"`
	} `json:"data"`
	Metadata struct {
		Entries []struct {
			Key   string `json:"key"`
			Label string `json:"label"`
			Type  string `json:"type"`
			Item  struct {
				Entries []struct {
					Key   string `json:"key"`
					Label string `json:"label,omitempty"`
					Type  string `json:"type"`
					Item  struct {
						Type    string `json:"type"`
						Entries []struct {
							Key   string `json:"key"`
							Label string `json:"label"`
							Type  string `json:"type"`
						} `json:"entries"`
					} `json:"item,omitempty"`
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
			Entries []struct {
				Key   string `json:"key"`
				Label string `json:"label"`
				Type  string `json:"type"`
			} `json:"entries,omitempty"`
		} `json:"entries"`
	} `json:"metadata"`
}

//EnrichCVE  performs a CVE search with RecordedFuture
func (m *TriageModule) EnrichCVE(ctx context.Context, vulnerability string, fields []string, metadata bool) (*CVEReport, error) {
	// Build URL
	values := url.Values{}
	values.Add("fields", strings.Join(fields, ","))
	values.Add("metadata", fmt.Sprintf("%v", metadata))
	URL := fmt.Sprintf("%s%v?%s", vulnerabilityEndpoint, vulnerability, values.Encode())

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

	reportHolder := &CVEReport{}
	err = json.NewDecoder(resp.Body).Decode(reportHolder)
	if err != nil {
		return nil, err
	}

	return reportHolder, nil
}

//cveMetaDataExtract gets the high level insights for CVE
func cveMetaDataExtract(rfCVEResults map[string]*CVEReport) []string {
	var triageMetaData, accessVectors []string
	riskCVE := 0
	affectedSystemsCPE := 0

	for cve, data := range rfCVEResults {
		// Add the RF Intelligence Card link to every CVE for easy access to people with access
		if data.Data.IntelCard != "" {
			triageMetaData = append(triageMetaData, fmt.Sprintf("RF Link for %s: %s", cve, data.Data.IntelCard))
		}

		// Calculate on risk score
		if data.Data.Risk.Score > 60 {
			riskCVE += 1
		}

		// keep count on the affected systems with the CPE's associated
		affectedSystemsCPE += len(data.Data.Cpe)

		// collect all the access vectors for the CVE's
		accessVectors = append(accessVectors, data.Data.Cvss.AccessVector)
	}

	if riskCVE > 0 {
		triageMetaData = append(triageMetaData, fmt.Sprintf("%d CVE's have a risk score > 60", riskCVE))
	}
	if affectedSystemsCPE > 0 {
		triageMetaData = append(triageMetaData, fmt.Sprintf("CPE's associated with list of CVE's : %d", affectedSystemsCPE))
	}
	if len(accessVectors) > 0 {
		triageMetaData = append(triageMetaData, fmt.Sprintf("Access Vectors for CVE's : %s", strings.Join(accessVectors, ",")))
	}
	return triageMetaData
}

//dumpCVECSV dumps the triage data to CSV
func dumpCVECSV(rfCVEResults map[string]*CVEReport) string {
	//Dump data as csv
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	csv.Write([]string{
		"IntelCardLink",
		"Risk Score",
		"Criticality",
		"CriticalityLabel",
		// TODO: Evidence Details- show it in a better way
		"CommonNames",
		"First Seen",
		"Last Seen",
		"ThreatLists",
		"Affected Machines: CPE",
		"RawRisk Rules Associated",
		"Access Vector",
		"Auth Required",
		"Access Complexity",
		"Confidentiality",
		"Integrity",
		"NVD Description",
		//TODO: "Analyst Notes- a better way to display",
	})
	for _, data := range rfCVEResults {
		// Processing few non string data before adding to CSV
		var threatLists, rawriskRules []string
		for _, threatlist := range data.Data.ThreatLists {
			threatLists = append(threatLists, threatlist.(string))
		}
		for _, rawrisk := range data.Data.Rawrisk {
			rawriskRules = append(rawriskRules, rawrisk.Rule)
		}

		cols := []string{
			data.Data.IntelCard,
			fmt.Sprintf("%d", data.Data.Risk.Score),
			fmt.Sprintf("%d", data.Data.Risk.Criticality),
			data.Data.Risk.CriticalityLabel,
			strings.Join(data.Data.CommonNames, " "),
			data.Data.Timestamps.FirstSeen.String(),
			data.Data.Timestamps.LastSeen.String(),
			strings.Join(threatLists, " "),
			strings.Join(data.Data.Cpe, " "),
			strings.Join(rawriskRules, " "),
			data.Data.Cvss.AccessVector,
			data.Data.Cvss.Authentication,
			data.Data.Cvss.AccessComplexity,
			data.Data.Cvss.Confidentiality,
			data.Data.Cvss.Integrity,
			data.Data.NvdDescription,
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}
