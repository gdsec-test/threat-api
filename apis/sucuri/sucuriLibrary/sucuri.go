package sucuriLibrary

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)


const (
	SucuriEndpoint = "https://sitecheck.sucuri.net/api/v3/?"
)

type SucuriReport struct {
	Scan struct {
		DbDate   time.Time `json:"db_date,omitempty"`
		Version  string    `json:"version,omitempty"`
		Duration float64   `json:"duration,omitempty"`
		LastScan time.Time `json:"last_scan,omitempty"`
	} `json:"scan,omitempty"`
	Site struct {
		IP          []string `json:"ip,omitempty"`
		Cdn         []string `json:"cdn,omitempty"`
		Input       string   `json:"input,omitempty"`
		Domain      string   `json:"domain,omitempty"`
		FinalURL    string   `json:"final_url,omitempty"`
		RunningOn   []string `json:"running_on,omitempty"`
		RedirectsTo []string `json:"redirects_to,omitempty"`
	} `json:"site,omitempty"`
	Ratings struct {
		Total struct {
			Rating string `json:"rating,omitempty"`
		} `json:"total,omitempty"`
		Domain struct {
			Passed string `json:"passed,omitempty"`
			Rating string `json:"rating,omitempty"`
		} `json:"domain,omitempty"`
		Security struct {
			Passed string `json:"passed,omitempty"`
			Rating string `json:"rating,omitempty"`
		} `json:"security,omitempty"`
	} `json:"ratings,omitempty"`
	Warnings struct {
		Security struct {
			Malware []struct {
				Msg      string `json:"msg,omitempty"`
				Type     string `json:"type,omitempty"`
				Details  string `json:"details,omitempty"`
				InfoURL  string `json:"info_url,omitempty"`
				Location string `json:"location,omitempty"`
			} `json:"malware,omitempty"`
		} `json:"security,omitempty"`
		ScanFailed []struct {
			Msg      string `json:"msg,omitempty"`
			Type     string `json:"type,omitempty"`
			Details  string `json:"details,omitempty"`
			InfoURL  string `json:"info_url,omitempty"`
			Location string `json:"location,omitempty"`
		} `json:"scan_failed,omitempty"`
	} `json:"warnings,omitempty"`
	Blacklists []struct {
		Vendor   string `json:"vendor,omitempty"`
		InfoURL  string `json:"info_url,omitempty"`
		Location string `json:"location,omitempty"`
	} `json:"blacklists,omitempty"`
	Recommendations struct {
		SecurityMinor struct {
			NeedsWaf struct {
			} `json:"needs_waf,omitempty"`
		} `json:"security_minor,omitempty"`
	} `json:"recommendations,omitempty"`
}


func GetSucuri(ctx context.Context, ioc string, SucuriClient *http.Client) (*SucuriReport, error) {
	// Build URL
	URL := SucuriEndpoint + "scan=" +  ioc
	URL = string(URL)


	// Build request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, URL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := SucuriClient.Do(req)
	if err != nil {
		return nil, err
	}


	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	reportHolder := &SucuriReport{}
	err = json.NewDecoder(resp.Body).Decode(reportHolder)
	if err != nil {
		return nil, err
	}


	return reportHolder, nil
}
