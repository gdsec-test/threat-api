package urlscanioLibrary

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	urlSubmissionEndpoint = "https://urlscan.io/api/v1/scan/"
)

type SubmissionResultHolder struct {
	Message    string `json:"message"`
	UUID       string `json:"uuid"`
	Result     string `json:"result"`
	API        string `json:"api"`
	Visibility string `json:"visibility"`
	Options    struct {
	} `json:"options"`
	URL string `json:"url"`
}

type ResultHolder struct {
	Data  interface{}
	Stats interface{} `json:"stats"`
	Meta  interface{} `json:"meta"`
	Task  struct {
		UUID          string        `json:"uuid"`
		Time          time.Time     `json:"time"`
		URL           string        `json:"url"`
		Visibility    string        `json:"visibility"`
		Method        string        `json:"method"`
		Source        string        `json:"source"`
		Tags          []interface{} `json:"tags"`
		ReportURL     string        `json:"reportURL"`
		ScreenshotURL string        `json:"screenshotURL"`
		DomURL        string        `json:"domURL"`
	} `json:"task"`
	Page struct {
		Url     string `json:"url"`
		Domain  string `json:"domain"`
		Country string `json:"country"`
		City    string `json:"city"`
		Server  string `json:"server"`
		IP      string `json:"ip"`
		Asn     string `json:"asn"`
		Asnname string `json:"asnname"`
	} `json:"page"`
	Lists    interface{} `json:"lists"`
	Verdicts struct {
		Overall struct {
			Score       int           `json:"score"`
			Categories  []interface{} `json:"categories"`
			Brands      []interface{} `json:"brands"`
			Tags        []interface{} `json:"tags"`
			Malicious   bool          `json:"malicious"`
			HasVerdicts int           `json:"hasVerdicts"`
		} `json:"overall"`
		Urlscan struct {
			Score            int           `json:"score"`
			Categories       []interface{} `json:"categories"`
			Brands           []interface{} `json:"brands"`
			Tags             []interface{} `json:"tags"`
			DetectionDetails []interface{} `json:"detectionDetails"`
			Malicious        bool          `json:"malicious"`
		} `json:"urlscan"`
		Engines struct {
			Score          int           `json:"score"`
			Malicious      []interface{} `json:"malicious"`
			Benign         []interface{} `json:"benign"`
			MaliciousTotal int           `json:"maliciousTotal"`
			BenignTotal    int           `json:"benignTotal"`
			Verdicts       []interface{} `json:"verdicts"`
			EnginesTotal   int           `json:"enginesTotal"`
		} `json:"engines"`
		Community struct {
			Score          int           `json:"score"`
			Votes          []interface{} `json:"votes"`
			VotesTotal     int           `json:"votesTotal"`
			VotesMalicious int           `json:"votesMalicious"`
			VotesBenign    int           `json:"votesBenign"`
			Tags           []interface{} `json:"tags"`
			Categories     []interface{} `json:"categories"`
		} `json:"community"`
	} `json:"verdicts"`
	Submitter interface{} `json:"submitter"`
}

type MetaData struct {
	MaliciousURLsCount      int
	MaliciousURLs           string
	BlacklistedDomainsCount int
	BlacklistedDomains      string
	URLsNotFoundCount       int
	URLsNotFound            string
	UnknownErrorCount       int
	UnknownErrorURL         string
}

func InitializeMetaData(ctx context.Context) *MetaData {
	metaDataHolder := &MetaData{}
	return metaDataHolder
}

func GetURLScanResults(ctx context.Context, ioc string, key string, urlscanClient *http.Client) (*ResultHolder, error) {
	// URL submission request
	reqBody := fmt.Sprintf(`{"url":"%s", "visibility":"public"}`, ioc)
	var jsonBody = []byte(reqBody)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlSubmissionEndpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("API-Key", key)

	resp, err := urlscanClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == 400 {
			bodyBytes, _ := io.ReadAll(resp.Body)
			bodyString := string(bodyBytes)
			if strings.Contains(bodyString, "Scan prevented") {
				return nil, fmt.Errorf("scan prevented")
			} else if strings.Contains(bodyString, "DNS Error") {
				return nil, fmt.Errorf("dns error")
			}
		} else {
			return nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
		}
	}

	submissionResultHolder := &SubmissionResultHolder{}
	err = json.NewDecoder(resp.Body).Decode(submissionResultHolder)
	if err != nil {
		return nil, err
	}

	api := submissionResultHolder.API

	// Urlscan.io Submission API takes up to 10 seconds to scan the URL and prepare its response
	time.Sleep(10 * time.Second)

	// Result API request to fetch url scan results
	scanReq, err := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
	if err != nil {
		return nil, err
	}

	scanResp, err := urlscanClient.Do(scanReq)
	if err != nil {
		return nil, err
	}

	for {
		if scanResp.StatusCode == 404 { // status when result is not ready
			time.Sleep(10 * time.Second) // sleep 10 seconds and try one more time later
			scanResp, err = urlscanClient.Do(scanReq)
			if err != nil {
				return nil, err
			}
		} else if scanResp.StatusCode != http.StatusOK { // handle other bad statuses
			return nil, fmt.Errorf("bad status code: %d", scanResp.StatusCode)
		}  else {
			break // get out of loop, cause result is ready
		}
	}

	// Initialize empty scanResponseHolder
	scanResponseHolder := &ResultHolder{}
	// Unmarshal JSON into empty scanResponseHolder
	buf := new(strings.Builder)
	_, err = io.Copy(buf, scanResp.Body)
	json.Unmarshal([]byte(buf.String()), scanResponseHolder)
	if err != nil {
		return nil, err
	}

	defer scanResp.Body.Close()

	return scanResponseHolder, nil
}
