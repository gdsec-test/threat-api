package main

import (
	"context"
	"fmt"
	"os"
	"testing"
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
