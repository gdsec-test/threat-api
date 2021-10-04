package zerobounceLibrary

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

const (
	zerobounceEndpoint = "https://api.zerobounce.net/v2/validate"
)

type ZeroBounceReport struct {
	Email         string      `json:"address"`
	Status        string      `json:"status"`
	SubStatus     string      `json:"sub_status"`
	FreeEmail     bool        `json:"free_email"`
	DidYouMean    interface{} `json:"did_you_mean"`
	Account       string      `json:"account"`
	Domain        string      `json:"domain"`
	DomainAgeDays string      `json:"domain_age_days"`
	SmtpProvider  string      `json:"smtp_provider"`
	MxFound       string      `json:"mx_found"`
	MxRecord      string      `json:"mx_record"`
	FirstName     interface{} `json:"firstname"`
	LastName      interface{} `json:"lastname"`
	Gender        interface{} `json:"gender"`
	Country       interface{} `json:"country"`
	Region        interface{} `json:"region"`
	City          interface{} `json:"city"`
	Zipcode       interface{} `json:"zipcode"`
	ProcessedAt   string      `json:"processed_at"`
}

func GetZeroBounce(ctx context.Context, ioc string, user string, key string, ZeroBounceClient *http.Client) (*ZeroBounceReport, error) {
	// Build URL
	values := url.Values{}
	values.Add("api_key", key)
	values.Add("email", ioc)
	URL := fmt.Sprintf("%s?%s", zerobounceEndpoint, values.Encode())

	// Build request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, URL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := ZeroBounceClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	reportHolder := &ZeroBounceReport{}
	err = json.NewDecoder(resp.Body).Decode(reportHolder)
	if err != nil {
		return nil, err
	}

	return reportHolder, nil
}
