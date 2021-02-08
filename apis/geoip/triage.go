package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

// TriageModule triage module
type TriageModule struct {
}

// GetDocs of this module
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "Performs a geoip lookup for IPs"}
}

// Supports returns true of we support this ioc type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{triage.IPType}
}

// Triage Finds geoip information given IPs
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	geoIPResults := Lookup(ctx, triageRequest.IOCs)

	triageData := &triage.Data{
		Title:    "GeoIP Data",
		Metadata: []string{},
	}

	if triageRequest.Verbose {
		result, err := json.Marshal(geoIPResults)
		if err != nil {
			triageData.Data = fmt.Sprintf("Error marshaling: %s", err)
			return []*triage.Data{triageData}, nil
		}
		triageData.Data = string(result)
		triageData.DataType = triage.JSONType
		return []*triage.Data{triageData}, nil
	}

	// Dump data as simplified csv instead
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	csv.Write([]string{
		"ip",
		"EnglishCity",
		"EnglishCountry",
		"ISOCountryCode",
		"TimeZone",
		"Lat",
		"Long",
	})

	for _, result := range geoIPResults {
		csv.Write([]string{
			result.IP,
			result.EnglishCity,
			result.EnglishCountry,
			result.ISOCountryCode,
			result.TimeZone,
			fmt.Sprintf("%.4f", result.Lat),
			fmt.Sprintf("%.4f", result.Long),
		})
	}
	csv.Flush()

	triageData.Data = resp.String()
	return []*triage.Data{triageData}, nil
}
