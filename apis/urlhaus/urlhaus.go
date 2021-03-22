package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/context/ctxhttp"
)

const (
	triageModuleName = "urlhaus"
	baseUrl          = "https://urlhaus.abuse.ch/feeds/asn/"
	urlhausExpiry    = 10 * time.Minute
	apiHashUrl       = "https://urlhaus-api.abuse.ch/v1/payload/"
	apiHostUrl       = "https://urlhaus-api.abuse.ch/v1/host/"
	apiUrlUrl        = "https://urlhaus-api.abuse.ch/v1/url/"
)

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

func QueryApi(ctx context.Context, apiUrl string, key string, value string) ([]byte, error) {
	//resp, err := http.PostForm(apiUrl, url.Values{key: {value}})
	resp, err := ctxhttp.PostForm(ctx, http.DefaultClient, apiUrl, url.Values{key: {value}})
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

func GetMd5(ctx context.Context, md5 string) (*UrlhausPayloadEntry, error) {
	body, err := QueryApi(ctx, apiHashUrl, "md5_hash", md5)
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
		return nil, fmt.Errorf("Query for %s returned no results (%s)", md5, entry.Status)
	}
	return &entry, nil
}

func GetSha256(ctx context.Context, sha256 string) (*UrlhausPayloadEntry, error) {
	body, err := QueryApi(ctx, apiHashUrl, "sha256_hash", sha256)
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

func GetDomainOrIp(ctx context.Context, host string) (*UrlhausHostEntry, error) {
	body, err := QueryApi(ctx, apiHostUrl, "host", host)
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

func GetUrl(ctx context.Context, _url string) (*UrlhausUrlEntry, error) {
	body, err := QueryApi(ctx, apiUrlUrl, "url", _url)
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
