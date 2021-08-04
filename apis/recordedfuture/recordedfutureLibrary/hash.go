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
	hashEndpoint = "https://api.recordedfuture.com/v2/hash/"
)

// HASHReportFields are the fields to submit to RF API to get a standard HASH report
var HASHReportFields = []string{"analystNotes", "counts", "enterpriseLists", "entity", "fileHashes", "hashAlgorithm", "intelCard", "links", "metrics", "relatedEntities", "risk", "riskMapping", "sightings", "threatLists", "timestamps"}

// HashReport is a sample report that recorded future returns when enriching a HASH
// if you request the fields HASHReportFields
type HashReport struct {
	Data struct {
		EnterpriseLists []interface{} `json:"enterpriseLists"`
		Sightings       []struct {
			Source    string    `json:"source"`
			URL       string    `json:"url"`
			Published time.Time `json:"published"`
			Fragment  string    `json:"fragment"`
			Title     string    `json:"title"`
			Type      string    `json:"type"`
		} `json:"sightings"`
		RiskMapping []struct {
			Rule       string `json:"rule"`
			Categories []struct {
				Framework string `json:"framework"`
				Name      string `json:"name"`
			} `json:"categories"`
		} `json:"riskMapping"`
		Entity struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"entity"`
		RelatedEntities []struct {
			Entities []struct {
				Count  int `json:"count"`
				Entity struct {
					ID   string `json:"id"`
					Name string `json:"name"`
					Type string `json:"type"`
				} `json:"entity"`
			} `json:"entities"`
			Type string `json:"type"`
		} `json:"relatedEntities"`
		AnalystNotes []struct {
			Attributes struct {
				ValidatedOn time.Time `json:"validated_on"`
				Published   time.Time `json:"published"`
				Text        string    `json:"text"`
				Attachment  string    `json:"attachment"`
				Topic       struct {
					ID          string `json:"id"`
					Name        string `json:"name"`
					Type        string `json:"type"`
					Description string `json:"description"`
				} `json:"topic"`
				ContextEntities []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
					Type string `json:"type"`
				} `json:"context_entities"`
				Title        string `json:"title"`
				NoteEntities []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
					Type string `json:"type"`
				} `json:"note_entities"`
			} `json:"attributes"`
			Source struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"source"`
			ID string `json:"id"`
		} `json:"analystNotes"`
		HashAlgorithm string `json:"hashAlgorithm"`
		Timestamps    struct {
			LastSeen  time.Time `json:"lastSeen"`
			FirstSeen time.Time `json:"firstSeen"`
		} `json:"timestamps"`
		ThreatLists []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Type        string `json:"type"`
			Description string `json:"description"`
		} `json:"threatLists"`
		Risk struct {
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
		FileHashes []string `json:"fileHashes"`
		IntelCard  string   `json:"intelCard"`
		Links      struct {
			Error string `json:"error"`
		} `json:"links"`
		Counts []struct {
			Date  string `json:"date"`
			Count int    `json:"count"`
		} `json:"counts"`
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
			Type string `json:"type"`
		} `json:"entries"`
	} `json:"metadata"`
}

//EnrichHASH  performs a HASH search with RecordedFuture
func EnrichHASH(ctx context.Context, RFKey string, RFClient *http.Client, hash string, fields []string, metadata bool) (*HashReport, error) {
	// Build URL
	values := url.Values{}
	values.Add("fields", strings.Join(fields, ","))
	values.Add("metadata", fmt.Sprintf("%v", metadata))
	URL := fmt.Sprintf("%s%v?%s", hashEndpoint, hash, values.Encode())

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

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	reportHolder := &HashReport{}
	err = json.NewDecoder(resp.Body).Decode(reportHolder)
	if err != nil {
		return nil, err
	}

	return reportHolder, nil
}
