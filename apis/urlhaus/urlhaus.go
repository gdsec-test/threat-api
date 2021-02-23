package main

import (
	"context"
	"encoding/csv"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	triageModuleName = "urlhaus"
	baseUrl          = "https://urlhaus.abuse.ch/feeds/asn/"
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
