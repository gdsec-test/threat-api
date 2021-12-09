package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	ptl "github.com/gdcorp-infosec/threat-api/apis/passivetotal/passivetotalLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	secretID         = "/ThreatTools/Integrations/passivetotal"
	triageModuleName = "passivetotal"
	passiveDNSURL    = "https://api.passivetotal.org"
)

// TriageModule triage module
type TriageModule struct {
	PTKey    string
	PTUser   string
	PTURL    string
	PTClient *http.Client
}

// GetDocs of this module
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "PassiveTotal data returning PassiveDNS data for past 1 year"}
}

// Supports returns true of we support this ioc type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{triage.DomainType, triage.IPType}
}

// Triage retrieves data from passivetotal
func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	triageDataPTData := &triage.Data{
		Title:    "PassiveDNS from Passivetotal",
		Metadata: []string{},
	}

	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	secret, err := tb.GetFromCredentialsStore(ctx, secretID, nil)
	if err != nil {
		triageDataPTData.Data = fmt.Sprintf("error in retrieving secrets: %s", err)
		return []*triage.Data{triageDataPTData}, err
	}

	secretMap := map[string]string{}
	if err := json.Unmarshal([]byte(*secret.SecretString), &secretMap); err != nil {
		triageDataPTData.Data = fmt.Sprintf("error in unmarshaling secrets: %s", err)
		return []*triage.Data{triageDataPTData}, err
	}

	if m.PTClient == nil {
		m.PTClient = http.DefaultClient
	}
	m.PTKey = secretMap["key"]
	m.PTUser = secretMap["user"]
	m.PTURL = passiveDNSURL

	var span *appsectracing.Span
	span, ctx = tb.TracerLogger.StartSpan(ctx, "PassiveTotal", "passivetotal", "services", "get")
	defer span.End(ctx)

	//retrieve PDNS results
	passiveDNSresults, err := m.GetPassiveDNS(ctx, triageRequest)
	if err != nil {
		triageDataPTData.Data = fmt.Sprintf("error from passivetotal: %s", err)
	} else {
		triageDataPTData.DataType = triage.JSONType
		var valArray []ptl.PassiveTotalResponse
		for _, val := range passiveDNSresults {
			valArray = append(valArray, *val.MakeDomainResponse())
		}
		a, _ := json.Marshal(valArray)
		b := string(a)
		fmt.Println(b)
	}

	return []*triage.Data{triageDataPTData}, nil
}
