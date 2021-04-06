package main

import (
	"context"
	"fmt"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
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
	var span *appsectracing.Span
	span, ctx = tb.TracerLogger.StartSpan(ctx, "TriageSplunk", "splunk", "splunk", "triage")
	defer span.End(ctx)

	// Check for reading splunk permission
	authorized, err := tb.Authorize(ctx, triageRequest.JWT, "ReadSplunk", m.GetDocs().Name)
	if err != nil {
		fmt.Printf("User not authorized: %s\n", err)
		return nil, nil
	}
	if !authorized {
		return []*triage.Data{{Title: "Splunk", Data: "Lacking permission.  You do not have permission to read splunk data."}}, nil
	}

	span, _ = tb.TracerLogger.StartSpan(ctx, "InitSplunkClient", "splunk", "client", "init")
	err = m.initClient(ctx)
	if err != nil {
		span.AddError(err)
		span.End(ctx)
		return nil, fmt.Errorf("Failed to log in to splunk: %s", err)
	}
	span.End(ctx)

	var triageDatas []*triage.Data

	switch triageRequest.IOCsType {
	case triage.GoDaddyUsernameType:
		span, ctx = tb.TracerLogger.StartSpan(ctx, "TriageUsernames", "splunk", "splunk", "triage")
		triageDatas = m.triageUsernames(ctx, triageRequest)
		span.End(ctx)
	case triage.CVEType:
		span, ctx = tb.TracerLogger.StartSpan(ctx, "TriageCVEs", "splunk", "splunk", "triage")
		triageDatas = m.triageCVEs(ctx, triageRequest)
		span.End(ctx)
	case triage.IPType:
		span, ctx = tb.TracerLogger.StartSpan(ctx, "TriageIPs", "splunk", "splunk", "triage")
		triageDatas = m.triageIPs(ctx, triageRequest)
		span.End(ctx)
	case triage.AWSHostnameType:
		span, ctx = tb.TracerLogger.StartSpan(ctx, "TriageAWSHostnames", "splunk", "splunk", "triage")
		triageDatas = m.triageAWSHostnames(ctx, triageRequest)
		span.End(ctx)
	}

	return triageDatas, nil
}
