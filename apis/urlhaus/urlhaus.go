package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"
	"time"
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

func FetchSingleAsn(asn string) ([]byte, error) {
	resp, err := http.Get(baseUrl + asn)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func DownloadAsn(ctx context.Context, asns []string) []*urlHausEntry {
	entries := []*urlHausEntry{}

	for _, asn := range asns {
		data, err := FetchSingleAsn(asn)
		if err != nil {
			continue
		}

		csvReader := csv.NewReader(strings.NewReader(data))
		csvReader.Comment = '#'
		records, err := csvReader.ReadAll()

		for _, field := range records {
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
