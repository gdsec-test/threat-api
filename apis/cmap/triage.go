package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"sort"
	"strings"

	"github.com/gdcorp-infosec/cmap-go/cmap"
	"github.com/gdcorp-infosec/go-sso-client/sso"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
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

func (m *TriageModule) DoDomainQuery(c *cmap.Client, ctx context.Context, domain string) (*cmap.DomainQuery, error) {
	return c.DoDomainQuery(ctx, domain)
}

// Triage Uses DCU's CMAP service to enrich shopper information about a GoDaddy domain
// It uses this library: https://github.com/gdcorp-infosec/cmap-go
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	triageData := &triage.Data{
		Title:    "GoDaddy Shopper Data",
		Metadata: []string{},
	}
	var span *appsectracing.Span

	// Check to make sure we have permission to do a cmap lookup
	span, _ = tb.TracerLogger.StartSpan(ctx, "CMAPAuth", "cmap", "auth", "authorize")
	if auth, err := tb.Authorize(ctx, triageRequest.JWT, "Run", triageModuleName); !auth {
		triageData.Data = "Permission denied.  You cannot run this module."
		span.LogKV("failedAuthReason", err)
		span.End(ctx)
		return []*triage.Data{triageData}, nil
	}
	span.End(ctx)

	// Build client
	span, _ = tb.TracerLogger.StartSpan(ctx, "BuildCMAPClient", "cmap", "client", "build")
	defer span.End(ctx)
	cmapCert := strings.ReplaceAll(m.CMAPCert, ":", "\n")
	cmapKey := strings.ReplaceAll(m.CMAPKey, ":", "\n")
	cert, err := tls.X509KeyPair([]byte(cmapCert), []byte(cmapKey))
	if err != nil {
		err = fmt.Errorf("error loading cmap cert: %w", err)
		span.AddError(err)
		return nil, err
	}
	c, err := cmap.New(ctx, cmap.ProdBaseURL, cert, sso.Production)
	if err != nil {
		err = fmt.Errorf("error creating cmap client: %s", err)
		span.AddError(err)
		return nil, err
	}
	span.End(ctx)

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

		// Process this domain
		span, _ = tb.TracerLogger.StartSpan(ctx, "CMAPDomainEnrich", "cmap", "domain", "enrich")
		result, err := m.DoDomainQuery(c, ctx, domain)
		if err != nil {
			err = fmt.Errorf("cmap lookup error: %w", err)
			span.AddError(err)
			span.End(ctx)
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
		span.End(ctx)
	}

	span, _ = tb.TracerLogger.StartSpan(ctx, "CMAPBuildMetadata", "cmap", "metadata", "build")
	if totalGoDaddyDomains == 0 {
		return []*triage.Data{triageData}, nil
	}

	if totalGoDaddyDomains > 0 {
		triageData.Metadata = append(triageData.Metadata, fmt.Sprintf("%d/%d domains are GoDaddy customer domains", totalGoDaddyDomains, len(triageRequest.IOCs)))
	}
	if totalGoDaddyDomains > 1 {
		triageData.Metadata = append(triageData.Metadata, fmt.Sprintf("Out of %d GoDaddy domains, they are owned by %d unique shoppers", totalGoDaddyDomains, len(customerCounts)))
	}

	// Sort by shopperID
	sort.Sort(&cmapResults)

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
	span.End(ctx)

	if auth, _ := tb.Authorize(ctx, triageRequest.JWT, "ViewPII", triageModuleName); !auth {
		triageData.Data = "Permission denied.  You are not in the correct group to see the real shopper data for each domain.  Reach out to #threat-research if you need the shopper data."
		return []*triage.Data{triageData}, nil
	}

	triageData.Data = response.String()
	return []*triage.Data{triageData}, nil
}
