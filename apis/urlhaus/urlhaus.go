package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

const (
	triageModuleName = "urlhaus"
	baseUrl          = "https://urlhaus.abuse.ch/feeds/asn/"
	urlhausExpiry    = 10 * time.Minute
	apiHashUrl       = "https://urlhaus-api.abuse.ch/v1/payload/"
	apiHostUrl       = "https://urlhaus-api.abuse.ch/v1/host/"
	apiUrlUrl        = "https://urlhaus-api.abuse.ch/v1/url/"
)

type urlHausEntry struct {
	Date      string
	URL       string
	URLStatus string
	Threat    string
	Tags      string
	Host      string
	IPAddress string
	ASnumber  string
	Country   string
}

type VirusTotalSubentry struct {
	Result  string  `json:"result"`
	Percent float32 `json:"percent,string"`
	Link    string  `json:"link"`
}

type UrlSubentry struct {
	Url       string `json:"url"`
	Status    string `json:"url_status"`
	Reference string `json:"urlhaus_reference"`
	FileName  string `json:"filename"`
	First     string `json:"firstseen"`
	Last      string `json:"lastseen"`
}

type UrlhausPayloadEntry struct {
	Status            string               `json:"query_status"`
	Md5               string               `json:"md5_hash"`
	Sha               string               `json:"sha256_hash"`
	FileType          string               `json:"file_type"`
	Size              int                  `json:"file_size,string"`
	Signature         string               `json:"signature"`
	First             string               `json:"first_seen"`
	Last              string               `json:"last_seen"`
	UrlCount          int                  `json:"url_count,string"`
	DownloadUrl       string               `json:"urlhaus_download"`
	VirusTotalResults []VirusTotalSubentry `json:"virustotal"`
	Imphash           string               `json:"imphash"`
	Ssdeep            string               `json:"ssdeep"`
	Tlsh              string               `json:"tlsh"`
	Urls              []UrlSubentry        `json:"urls"`
}

type UrlhausHostBlacklistSubentry struct {
	SurblStatus    string `json:"surbl"`
	SpamhausStatus string `json:"spamhaus_dbl"`
}

type UrlhausHostUrlSubentry struct {
	Id        string   `json:"id"`
	Reference string   `json:"urlhaus_reference"`
	Status    string   `json:"url_status"`
	Added     string   `json:"date_added"`
	Threat    string   `json:"threat"`
	Reporter  string   `json:"reporter"`
	Larted    string   `json:"larted"`
	Takedown  int      `json:"takedown_time_seconds,string"`
	Tags      []string `json:"tags"`
}

type UrlhausHostEntry struct {
	Status     string                       `json:"query_status"`
	Reference  string                       `json:"urlhaus_reference"`
	First      string                       `json:"first_seen"`
	Count      int                          `json:"url_count,string"`
	Blacklists UrlhausHostBlacklistSubentry `json:"blacklists"`
	Urls       []UrlhausHostUrlSubentry     `json:"urls"`
}

type UrlhausUrlPayloadSubentry struct {
	First      string             `json:"firstseen"`
	FileName   string             `json:"filename"`
	FileType   string             `json:"file_type"`
	Size       int                `json:"response_size,string"`
	Md5        string             `json:"response_md5"`
	Sha256     string             `json:"response_sha256"`
	Download   string             `json:"urlhaus_download"`
	Signature  string             `json:"signature"`
	VirusTotal VirusTotalSubentry `json:"virustotal"`
	Imphash    string             `json:"imphash"`
	Ssdeep     string             `json:"ssdeep"`
	Tlsh       string             `json:"tlsh"`
}

type UrlhausUrlEntry struct {
	Status     string                       `json:"query_status"`
	Id         string                       `json:"id"`
	Reference  string                       `json:"urlhaus_reference"`
	UrlStatus  string                       `json:"url_status"`
	Host       string                       `json:"host"`
	Added      string                       `json:"date_added"`
	Threat     string                       `json:"threat"`
	Blacklists UrlhausHostBlacklistSubentry `json:"blacklists"`
	Reporter   string                       `json:"reporter"`
	Larted     string                       `json:"larted"`
	Takedown   int                          `json:"takedown_time_seconds,string"`
	Tags       []string                     `json:"tags"`
	Payloads   []UrlhausUrlPayloadSubentry  `json:"payloads"`
}

func FetchSingleAsn(asn string) (string, error) {
	resp, err := http.Get(baseUrl + asn)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func QueryApi(apiUrl string, key string, value string) ([]byte, error) {
	resp, err := http.PostForm(apiUrl, url.Values{key: {value}})
	if err != nil {
		fmt.Printf("Error in POST: %s", err)
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error in reading response body: %s", err)
		return nil, err
	}
	return body, nil
}

/*
func DownloadAsns(ctx context.Context, asns []string) []*urlHausEntry {
	entries := []*urlHausEntry{}

	for _, asn := range asns {
		data, err := FetchSingleAsn(asn)
		if err != nil {
			continue
		}

		// URLhaus returns API queries as a CSV file
		csvReader := csv.NewReader(strings.NewReader(data))
		csvReader.Comment = '#'
		records, err := csvReader.ReadAll()

		for _, field := range records {
			// filter out the offline domains
			if field[2] == "online" {
				entry := &urlHausEntry{
					Date:      field[0],
					URL:       field[1],
					URLStatus: field[2],
					Threat:    field[3],
					Tags:      field[4],
					Host:      field[5],
					IPAddress: field[6],
					ASnumber:  field[7],
					Country:   field[8],
				}
				entries = append(entries, entry)
			}
		}
	}

	return entries
}
*/

func GetMd5(md5 string) (*UrlhausPayloadEntry, error) {
	body, err := QueryApi(apiHashUrl, "md5_hash", md5)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, errors.New("No error reported but the body was empty")
	}
	var entry UrlhausPayloadEntry
	err = json.Unmarshal(body, &entry)
	if err != nil {
		return nil, err
	}
	if entry.Status != "ok" {
		return nil, errors.New(fmt.Sprintf("Query for %s returned no results (%s)", md5, entry.Status))
	}
	return &entry, nil
}

func GetSha256(sha256 string) (*UrlhausPayloadEntry, error) {
	body, err := QueryApi(apiHashUrl, "sha256_hash", sha256)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, errors.New("No error reported but the body was empty")
	}
	var entry UrlhausPayloadEntry
	err = json.Unmarshal(body, &entry)
	if err != nil {
		return nil, err
	}
	if entry.Status != "ok" {
		return nil, errors.New(fmt.Sprintf("Query for %s returned no results (%s)", sha256, entry.Status))
	}
	return &entry, nil
}

func GetDomainOrIp(host string) (*UrlhausHostEntry, error) {
	body, err := QueryApi(apiHostUrl, "host", host)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, errors.New("No error reported but the body was empty")
	}
	var entry UrlhausHostEntry
	err = json.Unmarshal(body, &entry)
	if err != nil {
		return nil, err
	}
	if entry.Status != "ok" {
		return nil, errors.New(fmt.Sprintf("Query for %s returned no results (%s)", host, entry.Status))
	}
	return &entry, nil
}

func GetUrl(_url string) (*UrlhausUrlEntry, error) {
	body, err := QueryApi(apiUrlUrl, "url", _url)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, errors.New("No error reported but the body was empty")
	}
	var entry UrlhausUrlEntry
	err = json.Unmarshal(body, &entry)
	if err != nil {
		return nil, err
	}
	if entry.Status != "ok" {
		return nil, errors.New(fmt.Sprintf("Query for %s returned no results (%s)", _url, entry.Status))
	}
	return &entry, nil
}
