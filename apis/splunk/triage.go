package main

import (
	"context"
	"fmt"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
	"github.com/opentracing/opentracing-go"
	"github.com/vertoforce/go-splunk"
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
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	var span opentracing.Span
	span, ctx = opentracing.StartSpanFromContext(ctx, "TriageSplunk")
	defer span.Finish()

	// Check for reading splunk permission
	authorized, _ := tb.Authorize(ctx, triageRequest.JWT, "ReadSplunk", m.GetDocs().Name)
	if !authorized {
		return []*triage.Data{{Title: "Splunk", Data: "Lacking permission.  You do not have permission to read splunk data."}}, nil
	}

	err := m.initClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to log in to splunk: %s", err)
	}

	var triageDatas []*triage.Data

	switch triageRequest.IOCsType {
	case triage.GoDaddyUsernameType:
		triageDatas = m.triageUsernames(ctx, triageRequest)
	case triage.CVEType:
		triageDatas = m.triageCVEs(ctx, triageRequest)
	case triage.IPType:
		triageDatas = m.triageIPs(ctx, triageRequest)
	case triage.AWSHostnameType:
		triageDatas = m.triageAWSHostnames(ctx, triageRequest)
	}

	return triageDatas, nil
}
