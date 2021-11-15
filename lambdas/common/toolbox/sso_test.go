// +build !runTests

package toolbox

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
)

// For this test you need an env var named JWT with a valid JWT.
// This test just makes sure the request succeeds and gets > 0 groups.
func TestSSOGroups(t *testing.T) {
	testingJWT := os.Getenv("JWT")

	toolbox := GetToolbox()
	groups, err := toolbox.GetJWTGroups(context.Background(), testingJWT)
	if err != nil {
		t.Error(err)
		return
	}

	if len(groups) == 0 {
		t.Errorf("No groups found")
	}
}

func TestParseQueryParams(t *testing.T) {
	tests := []struct {
		Input  string
		Output map[string]string
	}{
		{Input: "Cookie1=mycookie;Cookie2=mycookie2;;;", Output: map[string]string{"Cookie1": "mycookie", "Cookie2": "mycookie2"}},
		{Input: "Cookie1=mycookie; Cookie2=mycookie2;;;", Output: map[string]string{"Cookie1": "mycookie", "Cookie2": "mycookie2"}},
		{Input: " Cookie1=mycookie; Cookie2=mycookie2; ;;", Output: map[string]string{"Cookie1": "mycookie", "Cookie2": "mycookie2"}},
		{Input: "Cookie1=mycookie=more;Cookie2=mycookie2;;;", Output: map[string]string{"Cookie1": "mycookie=more", "Cookie2": "mycookie2"}},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			cookies := parseQueryParams(test.Input)
			if !reflect.DeepEqual(cookies, test.Output) {
				t.Errorf("expected %v but got %v", test.Output, cookies)
				t.Fail()
			}
		})
	}
}

// TestAuthorize Tests the authorize functionality.
// The assumption of this test is that the TESTING_JWT CAN perform the
// `test` action on `geoip` but doesn't have any other permissions.
// To perform that action the JWT should be part of the `Eng-ThreatIntel` group.
// (As the current lambda metadata for geoip)
func TestAuthorize(t *testing.T) {
	toolbox := GetToolbox()
	testingJWT := os.Getenv("TESTING_JWT")

	tests := []struct {
		Action         string
		Resource       string
		ExpectedResult bool
	}{
		{"test", "geoip", true},
		{"test2", "geoip", false},
		{"test", "lambda", false},
	}

	for i, test := range tests {
		result, err := toolbox.Authorize(context.Background(), testingJWT, test.Action, test.Resource)
		if result != test.ExpectedResult {
			t.Errorf("Test %d failed. Tried to %s on %s, expected %v but got %v. Err: %s", i, test.Action, test.Resource, test.ExpectedResult, result, err)
		}
	}
}
