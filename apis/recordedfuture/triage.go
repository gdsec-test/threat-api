package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
	"net/http"
)

// CVEReportFields are the fields to submit to get a standard CVE report
var CVEReportFields = []string{"analystNotes", "commonNames", "counts", "rawrisk", "cvssv3", "cpe22uri", "cvss", "enterpriseLists", "cpe", "entity", "intelCard", "metrics", "nvdDescription", "relatedEntities", "relatedLinks", "risk", "sightings", "threatLists", "timestamps"}

//IPReportFields are the fields to submit to get a standard IP report
var IPReportFields = []string{"analystNotes", "counts", "enterpriseLists", "entity", "intelCard", "location", "metrics", "relatedEntities", "risk", "riskyCIDRIPs", "sightings", "threatLists", "timestamps"}

//tb Toolbox to use secrets manager
var tb *toolbox.Toolbox

// TODO: Add tracing after IP Triaging

const (
	secretID     = "/ThreatTools/Integrations/recordedfuture"
	versionStage = "AWSCURRENT"
)

// TriageModule triage module
type TriageModule struct {
	RFKey    string
	RFClient *http.Client
}

// GetDocs of this module
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "Recorded Future triages CVE currently"}
}

// Supports returns true of we support this ioc type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{triage.CVEType, triage.IPType}
}

// Triage pulls information from RecordedFuture ConnectAPI
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	triageData := &triage.Data{
		Title:    "Recorded Future Data",
		Metadata: []string{},
	}
	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	secret, err := tb.GetFromCredentialsStore(ctx, secretID, versionStage)
	if err != nil {
		triageData.Data = fmt.Sprintf("error in retrieving secrets: %s", err)
		return []*triage.Data{triageData}, err
	}

	m.RFKey = *secret.SecretString
	if m.RFClient == nil {
		m.RFClient = http.DefaultClient
	}

	rfCVEResults := make(map[string]*CVEReport)

	if triageRequest.IOCsType == triage.CVEType {
		for _, vulnerability := range triageRequest.IOCs {
			// Check context
			select {
			case <-ctx.Done():
				break
			default:
			}

			rfCVEResult, err := m.EnrichCVE(ctx, vulnerability, CVEReportFields, true)
			if err != nil {
				rfCVEResults[vulnerability] = nil
				continue
			}
			rfCVEResults[vulnerability] = rfCVEResult
		}
	}

	if triageRequest.IOCsType == triage.IPType {
		for _, ip := range triageRequest.IOCs {
			// Check context
			select {
			case <-ctx.Done():
				break
			default:
			}
			// TODO : IP triaging
			fmt.Printf(ip)
		}
	}

	// Dump full data if we are doing full dump
	if triageRequest.Verbose {
		result, err := json.Marshal(rfCVEResults)
		if err != nil {
			triageData.Data = fmt.Sprintf("Error marshaling: %s", err)
			return []*triage.Data{triageData}, nil
		}
		triageData.Data = string(result)
		triageData.DataType = triage.JSONType
		return []*triage.Data{triageData}, nil
	}

	//Add metadata
	triageData.Metadata = cveMetaDataExtract(rfCVEResults)

	triageData.Data = dumpCVECSV(rfCVEResults)
	return []*triage.Data{triageData}, nil
}

//cveMetaDataExtract gets the high level insights for CVE
func cveMetaDataExtract(rfCVEResults map[string]*CVEReport) []string {
	var triageMetaData []string
	riskCVE := 0

	for _, data := range rfCVEResults {
		if data.Data.Risk.Score > 60 {
			riskCVE += 1
		}
	}

	if riskCVE > 0 {
		triageMetaData = append(triageMetaData, fmt.Sprintf("%d CVE's have a risk score > 60", riskCVE))
	}
	return triageMetaData
}

//dumpCVECSV dumps the triage data to CSV
func dumpCVECSV(rfCVEResults map[string]*CVEReport) string {
	//Dump data as csv
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	csv.Write([]string{
		"Risk Score",
		"Criticality",
		"Access Vector",
		"Auth Required",
		"Complexity",
		"Description",
	})
	for _, data := range rfCVEResults {
		cols := []string{
			fmt.Sprintf("%d", data.Data.Risk.Score),
			fmt.Sprintf("%d", data.Data.Risk.Criticality),
			data.Data.Cvss.AccessVector,
			data.Data.Cvss.Authentication,
			data.Data.Cvss.AccessComplexity,
			data.Data.Entity.Description,
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}
