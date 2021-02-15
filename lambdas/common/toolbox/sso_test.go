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

func TestParseCookies(t *testing.T) {
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
			cookies := parseCookies(test.Input)
			if !reflect.DeepEqual(cookies, test.Output) {
				t.Errorf("expected %v but got %v", test.Output, cookies)
				t.Fail()
			}
		})
	}
}
