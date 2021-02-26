package main

import (
	"context"
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
	return &triage.Doc{Name: triageModuleName, Description: "Recorded Future triages CVE, IP"}
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

	if triageRequest.IOCsType == triage.CVEType {
		rfCVEResults := make(map[string]*CVEReport)
		for _, cve := range triageRequest.IOCs {
			// Check context
			select {
			case <-ctx.Done():
				break
			default:
			}

			// Calling RF API with metadata switched off
			rfCVEResult, err := m.EnrichCVE(ctx, cve, CVEReportFields, false)
			if err != nil {
				rfCVEResults[cve] = nil
				continue
			}
			rfCVEResults[cve] = rfCVEResult
		}

		// Add the results
		triageData.Metadata = cveMetaDataExtract(rfCVEResults)

		// if verbose wasn't requested dump csv here
		if !triageRequest.Verbose {
			triageData.DataType = triage.CSVType
			triageData.Data = dumpCVECSV(rfCVEResults)
		}
	}

	if triageRequest.IOCsType == triage.IPType {
		rfIPResults := make(map[string]*IPReport)
		for _, ip := range triageRequest.IOCs {
			// Check context
			select {
			case <-ctx.Done():
				break
			default:
			}

			rfIPResult, err := m.EnrichIP(ctx, ip, IPReportFields, false)
			if err != nil {
				rfIPResults[ip] = nil
				continue
			}
			rfIPResults[ip] = rfIPResult
		}
		// Add the results
		triageData.Metadata = ipMetaDataExtract(rfIPResults)

		// if verbose wasn't requested dump csv here
		if !triageRequest.Verbose {
			triageData.DataType = triage.CSVType
			triageData.Data = dumpIPCSV(rfIPResults)
		}
	}

	return []*triage.Data{triageData}, nil
}
