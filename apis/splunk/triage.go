package main

import (
	"context"
	"fmt"

	"github.com/vertoforce/go-splunk"
	"github.secureserver.net/threat/core"
	"github.secureserver.net/threat/threatapi/triage/modules/triage"
)

const (
	triageModuleName = "splunk"
)

// TriageModule Module
type TriageModule struct {
	SplunkUsername string
	SplunkPassword string
	SplunkBaseURL  string

	splunkClient *splunk.Client

	// RequiredGroups needed to view splunk data
	RequiredGroups []string
}

// GetDocs of this module
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "Searches relevant indices and logs for mentioned of the IOC (ex: past logins, vpc logs, etc)"}
}

// Supports returns true of we support this ioc type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{triage.GoDaddyUsernameType, triage.CVEType, triage.IPType, triage.AWSHostnameType}
}

// Triage takes some ioc and finds what we can in splunk
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request, api *core.Api) ([]*triage.Data, error) {
	triage.Log(triageModuleName, "TriageSplunk", api, core.LogFields{"count": len(triageRequest.IOCs)})

	// Check permissions first incase the context is canceled
	// We still get the data to let the user know there was data found that they can't view
	hasPermission := api.UserInRequiredGroups(ctx, triageRequest.Username, m.RequiredGroups)

	err := m.initClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to log in to splunk: %s", err)
	}

	var triageDatas []*triage.Data

	switch triageRequest.IOCsType {
	case triage.GoDaddyUsernameType:
		triageDatas = m.triageUsernames(ctx, triageRequest, api)
	case triage.CVEType:
		triageDatas = m.triageCVEs(ctx, triageRequest, api)
	case triage.IPType:
		triageDatas = m.triageIPs(ctx, triageRequest, api)
	case triage.AWSHostnameType:
		triageDatas = m.triageAWSHostnames(ctx, triageRequest, api)
	}

	if len(triageDatas) > 0 {
		// Check to make sure we have permission to view this data
		if !hasPermission {
			return []*triage.Data{{
				Title:    "Splunk",
				Metadata: []string{"Insights that you do not have permissions to view.  Contact the threat team to access this information"},
			}}, nil
		}
	}

	return triageDatas, nil
}
