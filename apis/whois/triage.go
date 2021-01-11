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
	return &triage.Doc{Name: triageModuleName, Description: "Performs a whois lookup on domains"}
}

// Supports returns true of we support this ioc type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{triage.DomainType}
}

// Triage Finds whois information from a list of domains
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	whoisResults, stats := Lookup(ctx, triageRequest.IOCs)

	triageData := &triage.Data{
		Title:    "Whois lookup data",
		Metadata: []string{},
	}

	// Add some metadata if we found something interesting in the whois stats
	validDomains := len(triageRequest.IOCs) - stats.InvalidDomains
	if validDomains != len(stats.SameRegistrant) {
		// Some domains have the same registrant
		triageData.Metadata = append(triageData.Metadata, fmt.Sprintf("Out of %d valid domains, they are owned by %d unique registrants", validDomains, len(stats.SameRegistrant)))
	}
	if validDomains != len(stats.SameRegistrar) {
		// Some domains have the same registrar
		triageData.Metadata = append(triageData.Metadata, fmt.Sprintf("Out of %d valid domains, they are registered by %d unique registrars", validDomains, len(stats.SameRegistrar)))
	}
	if stats.InvalidDomains > 0 {
		triageData.Metadata = append(triageData.Metadata, fmt.Sprintf("%d/%d Domains are invalid (bad whois data)", stats.InvalidDomains, len(triageRequest.IOCs)))
	}

	// Dump full data if we are doing full dump
	if triageRequest.Verbose {
		result, err := json.Marshal(whoisResults)
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
		"domain",
		"createdDate",
		"updatedDate",
		"expirationDate",
		"registrarName",
		"registrarEmail",
		"registrarPhone",
		"registrantName",
		"registrantEmail",
		"registrantPhone",
		"registrantOrganization",
		"registrantStreet",
		"registrantCity",
		"registrantCountry",
		"administrativeOrganization",
	})

	// Write each domain whois info
	for _, result := range whoisResults {
		csv.Write([]string{
			result.Domain.Domain,
			result.Domain.CreatedDate,
			result.Domain.UpdatedDate,
			result.Domain.ExpirationDate,
			result.Registrar.Name,
			result.Registrar.Email,
			result.Registrar.Phone,
			result.Registrant.Name,
			result.Registrant.Email,
			result.Registrant.Phone,
			result.Registrant.Organization,
			result.Registrant.Street,
			result.Registrant.City,
			result.Registrant.Country,
			result.Administrative.Organization,
		})
	}
	csv.Flush()

	triageData.Data = resp.String()
	return []*triage.Data{triageData}, nil
}
