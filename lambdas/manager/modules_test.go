package main

import (
	"context"
	"testing"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
	"github.com/gdcorp-infosec/threat-util/lambda/toolbox"
)

// Test getting modules and all their metadata
func TestGetModules(t *testing.T) {
	results, err := getModules(context.Background(), toolbox.GetToolbox())
	if err != nil {
		t.Fatal(err)
	}

	if len(results) == 0 {
		t.Fatalf("no results returned")
	}

	// Check to make sure there exists a result that supports ip
	// This isn't a true test, and you should really check what results is in the debugger,
	// but it's a good sanity check
	t.Run("CheckForIPType", func(t *testing.T) {
		for _, metadata := range results {
			for _, iocType := range metadata.SupportedIOCTypes {
				if iocType == triage.IPType {
					return
				}
			}
		}
		t.Fatalf("no module that supports ip")
	})
}
