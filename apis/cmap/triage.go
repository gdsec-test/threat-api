package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.secureserver.net/clake1/cmap-go/cmap"
	"github.secureserver.net/go/sso-client/sso"
	"github.secureserver.net/threat/core"
	"github.secureserver.net/threat/core/common"
	"github.secureserver.net/threat/threatapi/triage/modules/triage"
)

const (
	triageModuleName = "cmap"
)

// TriageModule triage module
type TriageModule struct {
	// Certificate authentication to CMAP API
	CMAPCert string
	CMAPKey  string
}

// GetDocs of this module
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "Searches DCU's CMAP service to get customer data on domains"}
}

// Supports returns true of we support this ioc type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{triage.DomainType}
}

// Triage Uses DCU's CMAP service to enrich shopper information about a GoDaddy domain
// It uses this library: https://github.secureserver.net/clake1/cmap-go
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	triageData := &triage.Data{
		Title:    "GoDaddy Shopper Data",
		Metadata: []string{},
	}

	// Build client
	cmapCert := strings.ReplaceAll(m.CMAPCert, ":", "\n")
	cmapKey := strings.ReplaceAll(m.CMAPKey, ":", "\n")
	cert, err := tls.X509KeyPair([]byte(cmapCert), []byte(cmapKey))
	if err != nil {
		api.Error("ErrorLoadingCMAPCert", core.LogFields{"error": err})
		return nil, fmt.Errorf("error loading cmap cert: %s", err)
	}
	c, err := cmap.New(ctx, cmap.ProdBaseURL, cert, sso.Production)
	if err != nil {
		api.Error("ErrorCreatingCMAPClient", core.LogFields{"error": err})
		return nil, fmt.Errorf("error creating cmap client: %s", err)
	}

	// Process domains
	cmapResults := cmapResultsType{}
	// Keep track of how many domains belong to each customer
	customerCounts := map[string]int{}
	totalGoDaddyDomains := 0
	for _, domain := range triageRequest.IOCs {
		// Check context
		select {
		case <-ctx.Done():
			break
		default:
		}

		triage.Log(triageModuleName, "CMAPDomainEnrich", api, core.LogFields{
			"domain": domain,
		})
		result, err := c.DoDomainQuery(ctx, domain)
		if err != nil {
			api.Error("CMAPLookupError", core.LogFields{"error": err, "domain": domain})
			// TODO: Add error entry to results
			continue
		}

		// Count this towards a shopper
		if result.DomainQuery.ShopperID != "" {
			totalGoDaddyDomains++
			if _, ok := customerCounts[string(result.DomainQuery.ShopperID)]; ok {
				customerCounts[string(result.DomainQuery.ShopperID)]++
			} else {
				customerCounts[string(result.DomainQuery.ShopperID)] = 1
			}
		}

		cmapResults = append(cmapResults, result)
	}

	if totalGoDaddyDomains == 0 {
		return []*triage.Data{triageData}, nil
	}

	if totalGoDaddyDomains > 0 {
		triageData.Metadata = append(triageData.Metadata, fmt.Sprintf("%d/%d domains are GoDaddy customer domains", totalGoDaddyDomains, len(triageRequest.IOCs)))
	}
	if totalGoDaddyDomains > 1 {
		triageData.Metadata = append(triageData.Metadata, fmt.Sprintf("Out of %d GoDaddy domains, they are owned by %d unique shoppers", totalGoDaddyDomains, len(customerCounts)))
	}

	// Check to make sure we have permission to list the actual shopper data
	if !api.UserInRequiredGroups(ctx, triageRequest.Username, m.RequiredGroups) {
		triageData.Data = "Permission denied.  You are not in the correct group to see the real shopper data for each domain.  Reach out to #threat if you need the shopper data."
		return []*triage.Data{triageData}, nil
	}

	// Sort by shopperID
	sort.Sort(&cmapResults)

	if triageRequest.Verbose {
		// Write response as JSON
		json, err := json.Marshal(cmapResults)
		if err != nil {
			api.Error("MarshalError", core.LogFields{"error": err})
			return nil, fmt.Errorf("error marshaling: %s", err)
		}
		triageData.Data = common.IndentJSON(string(json))
		triageData.DataType = triage.JSONType
		return []*triage.Data{triageData}, nil
	}

	// Write response as csv
	response := bytes.Buffer{}
	csv := csv.NewWriter(&response)
	// Write headers
	headers := []string{"domain", "shopper_id", "first name", "last name", "address1", "address2", "city", "state", "postal code", "country", "domain status"}
	csv.Write(headers)

	for _, result := range cmapResults {
		if result.DomainQuery.ShopperID == "" {
			// Skip rows that are not godaddy domains
			continue
		}
		csv.Write([]string{
			string(result.DomainQuery.Domain),
			string(result.DomainQuery.ShopperID),
			string(result.DomainQuery.ShopperInfo.ShopperFirstName),
			string(result.DomainQuery.ShopperInfo.ShopperLastName),
			string(result.DomainQuery.ShopperInfo.ShopperAddress1),
			string(result.DomainQuery.ShopperInfo.ShopperAddress2),
			string(result.DomainQuery.ShopperInfo.ShopperCity),
			string(result.DomainQuery.ShopperInfo.ShopperState),
			string(result.DomainQuery.ShopperInfo.ShopperPostalCode),
			string(result.DomainQuery.ShopperInfo.ShopperCountry),
			string(result.DomainQuery.DomainStatus.StatusCode),
		})
	}
	csv.Flush()

	triageData.Data = response.String()
	return []*triage.Data{triageData}, nil
}
