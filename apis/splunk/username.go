package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"time"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
	"github.com/opentracing/opentracing-go"
	"github.com/vertoforce/go-splunk"
)

const (
	// This searches okta logs based on a username for login events
	recentOktaLoginsByUsernameSearch = `index=oktalogs user="%s@godaddy.com" displayMessage="User single sign on to app" | table _time user src_ip app displayMessage actor.displayName client.userAgent.browser | sort -_time`
	// Number of days to look back
	recentLoginsBackcheckDays = 10
)

// LoginEvent is a login event from splunk of an okta user
type LoginEvent struct {
	User        string    `splunk:"user"`
	Time        time.Time `splunk:"_time"`
	SrcIP       string    `splunk:"src_ip"`
	DisplayName string    `splunk:"actor.displayName"`
	AppName     string    `splunk:"app"`
	UserAgent   string    `splunk:"client.userAgent.browser"`
}

// GetRecentLoginEvents Crafts a splunk job and performs it finding any interesting entries involving a username
func (m *TriageModule) GetRecentLoginEvents(ctx context.Context, username string) (chan *LoginEvent, error) {
	searchJob, err := m.splunkClient.CreateSearchJob(ctx,
		fmt.Sprintf(recentOktaLoginsByUsernameSearch, username),
		map[string]string{
			"earliest_time": splunk.FormatTime(time.Now().Add(-time.Hour * 24 * recentLoginsBackcheckDays)),
		})
	if err != nil {
		return nil, err
	}

	results, err := searchJob.GetResults(ctx)
	if err != nil {
		return nil, err
	}

	// Create channel that converts results to our channel type
	loginEvents := make(chan *LoginEvent)
	go func() {
		defer close(loginEvents)
		defer searchJob.Delete(context.Background())
		for result := range results {
			loginEvent := LoginEvent{}

			// Populate struct
			err = result.UnMarshal(&loginEvent)
			if err != nil {
				continue
			}

			select {
			case loginEvents <- &loginEvent:
			case <-ctx.Done():
				return
			}

		}

	}()

	return loginEvents, nil
}

// triageUsernames triages information from splunk given a username
func (m *TriageModule) triageUsernames(ctx context.Context, triageRequest *triage.Request) []*triage.Data {
	triageData := &triage.Data{Metadata: []string{}}

	triageData.DataType = triage.CSVType
	triageData.Title = "Recent Logins"

	// Build CSV
	csvData := &bytes.Buffer{}
	csvWriter := csv.NewWriter(csvData)
	// Write Headers
	csvData.WriteString(fmt.Sprintf("# This data is only from the last %d days since %s\n", recentLoginsBackcheckDays, time.Now().UTC().String()))
	csvWriter.Write([]string{"Time", "username", "displayName", "srcIP", "app", "userAgent"})

	// Perform for each username
	for _, username := range triageRequest.IOCs {
		var span opentracing.Span
		span, ctx = opentracing.StartSpanFromContext(ctx, "CheckSplunkUsername")
		// Find recent logins
		loginEvents, err := m.GetRecentLoginEvents(ctx, username)
		if err != nil {
			span.LogKV("error", "SplunkCheckFailure")
			span.LogKV("errorMessage", err.Error())
			span.Finish()
			continue
		}

		// The first event should be the most recent
		var firstLoginEvent *LoginEvent
		totalLogins := 0
		for loginEvent := range loginEvents {
			if firstLoginEvent == nil {
				copy := *loginEvent
				firstLoginEvent = &copy
			}
			csvWriter.Write([]string{loginEvent.Time.String(), username, loginEvent.DisplayName, loginEvent.SrcIP, loginEvent.AppName, loginEvent.UserAgent})
			totalLogins++
		}
		if firstLoginEvent != nil {
			triageData.Metadata = append(triageData.Metadata,
				fmt.Sprintf("`%s` (%s)'s last okta login was on *%s* (UTC) to *%s* from *%s* user agent *%s*.  They have logged in *%d* times in the last *%d* days",
					username,
					firstLoginEvent.DisplayName,
					firstLoginEvent.Time.Format("01/02/2006 15:04:05"),
					firstLoginEvent.AppName,
					firstLoginEvent.SrcIP,
					firstLoginEvent.UserAgent,
					totalLogins,
					recentLoginsBackcheckDays,
				))
		}
		span.Finish()
	}

	csvWriter.Flush()
	triageData.Data = csvData.String()

	return []*triage.Data{triageData}
}
