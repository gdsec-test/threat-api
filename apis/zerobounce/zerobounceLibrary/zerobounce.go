package zerobounceLibrary

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	zerobounceEndpoint = "https://bulkapi.zerobounce.net/v2/validatebatch"
)

type ZeroBounceReport struct {
	EmailBatch []struct {
		Address       string      `json:"address"`
		Status        string      `json:"status"`
		SubStatus     string      `json:"sub_status"`
		FreeEmail     bool        `json:"free_email"`
		DidYouMean    interface{} `json:"did_you_mean"`
		Account       string      `json:"account"`
		Domain        string      `json:"domain"`
		DomainAgeDays string      `json:"domain_age_days"`
		SMTPProvider  string      `json:"smtp_provider"`
		MxFound       string      `json:"mx_found"`
		MxRecord      string      `json:"mx_record"`
		Firstname     string      `json:"firstname"`
		Lastname      string      `json:"lastname"`
		Gender        string      `json:"gender"`
		Country       interface{} `json:"country"`
		Region        interface{} `json:"region"`
		City          interface{} `json:"city"`
		Zipcode       interface{} `json:"zipcode"`
		ProcessedAt   string      `json:"processed_at"`
	} `json:"email_batch"`
	Errors []interface{} `json:"errors"`
}

type MetaData struct {
	ValidAccounts     int
	InvalidAccounts   int
	CatchAllAccounts  int
	SpamTrapAccounts  int
	AbuseAccounts     int
	DoNotMailAccounts int
	UnkownAccounts    int
}

func InitializeMetaData(ctx context.Context) *MetaData {
	metaData := &MetaData{}
	return metaData
}


func GetZeroBounce(ctx context.Context, iocList string, user string, key string, ZeroBounceClient *http.Client) (*ZeroBounceReport, error) {
	// Build JSON request body
	reqBody := fmt.Sprintf(`{"api_key":"%s", %s}`, key, iocList)
	var jsonBody = []byte(reqBody)

	// Build request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, zerobounceEndpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ZeroBounceClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		reportHolder := &ZeroBounceReport{}
		return reportHolder, nil
	}

	reportHolder := &ZeroBounceReport{}
	err = json.NewDecoder(resp.Body).Decode(reportHolder)
	if err != nil {
		return nil, err
	}

	return reportHolder, nil
}
