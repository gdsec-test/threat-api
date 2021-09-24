// +build !runTests

package main

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

func TestSplunk(t *testing.T) {
	m := &TriageModule{
		SplunkUsername: os.Getenv("SPLUNK_USERNAME"),
		SplunkPassword: os.Getenv("SPLUNK_PASSWORD"),
		SplunkBaseURL:  os.Getenv("SPLUNK_BASEURL"),
	}
	err := m.initClient(context.Background())
	if err != nil {
		t.Error(err)
		return
	}

	results, err := m.GetRecentLoginEvents(context.Background(), "clake1")
	if err != nil {
		t.Error(err)
		return
	}
	for result := range results {
		fmt.Println(result)
	}
}

// TestSplunkAWS is used to test splunk functionality including AWS functionality.
// It does require some manual testing.
func TestSplunkAWS(t *testing.T) {
	tb = toolbox.GetToolbox()
	defer tb.Close(context.Background())

	tm := &TriageModule{
		SplunkUsername: os.Getenv("SPLUNK_USERNAME"),
		SplunkPassword: os.Getenv("SPLUNK_PASSWORD"),
		SplunkBaseURL:  os.Getenv("SPLUNK_BASEURL"),
	}
	triageData, err := tm.Triage(context.Background(), &triage.Request{
		IOCs:     []string{"1.1.1.1"},
		IOCsType: triage.IPType,
		JWT:      os.Getenv("TESTING_JWT"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(triageData) == 0 {
		t.Fatalf("no data returned")
	}
}

func TestRawHandler(t *testing.T) {
	_, err := handler(context.Background(), events.SNSEvent{})
	if err != nil {
		t.Fatal(err)
	}
}
