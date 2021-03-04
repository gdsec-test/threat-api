package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"strings"
	"time"

	"github.com/vertoforce/go-splunk"
	"github.secureserver.net/threat/core"
	"github.secureserver.net/threat/threatapi/triage/modules/triage"
)

const (
	splunkCVESearch = `index="on_prem" sourcetype=deepsecurity alert="*%s*" | rex field=alert ".*(?P<CVE>CVE-\d{4}-\d+)" | table _time CVE alert dst src dpt spt | sort -_time`
	// Limit on results from splunk query
	rowLimit = 500
)

// CVEEvent is some mention of a CVE in splunk logs
type CVEEvent struct {
	Alert           string    `splunk:"alert"`
	Time            time.Time `splunk:"_time"`
	CVE             string    `splunk:"CVE"`
	DestinationIP   string    `splunk:"dst"`
	SourceIP        string    `splunk:"src"`
	DestinationPort int       `splunk:"dpt"`
	SourcePort      int       `splunk:"spt"`
}

// RecentCVEEvents Finds recent CVE events in splunk.  They are usually deep security firewall alerts
func (m *TriageModule) RecentCVEEvents(ctx context.Context, CVE string) (chan *CVEEvent, error) {
	CVE = strings.ToUpper(CVE)
	searchJob, err := m.splunkClient.CreateSearchJob(ctx,
		fmt.Sprintf(splunkCVESearch, CVE),
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
	events := make(chan *CVEEvent)
	go func() {
		defer close(events)
		// Remove the job at the end, if results are done or if job is canceled
		defer searchJob.Delete(context.Background())
		for result := range results {
			event := CVEEvent{
				CVE: CVE,
			}

			// Populate struct
			err = result.UnMarshal(&event)
			if err != nil {
				continue
			}

			select {
			case events <- &event:
			case <-ctx.Done():
				return
			}
		}

	}()

	return events, nil
}

// triageCVEs triages information from splunk given a CVE
func (m *TriageModule) triageCVEs(ctx context.Context, triageRequest *triage.Request, api *core.Api) []*triage.Data {
	triageData := &triage.Data{Metadata: []string{}}

	triageData.DataType = triage.CSVType
	triageData.Title = "Recent CVEs found in splunk logs"

	// Build CSV
	csvData := &bytes.Buffer{}
	csvWriter := csv.NewWriter(csvData)
	// Write Headers
	csvData.WriteString(fmt.Sprintf("# This data is only from the last %d days since %s\n", recentLoginsBackcheckDays, time.Now().UTC().String()))
	csvWriter.Write([]string{"Time", "CVE", "DestinationIP", "SourceIP", "DestinationPort", "SourcePort", "Alert"})

	for _, CVE := range triageRequest.IOCs {
		spunkSearchContext, cancelSplunkSearch := context.WithCancel(ctx)
		cveEvents, err := m.RecentCVEEvents(spunkSearchContext, CVE)
		if err != nil {
			triage.Log(m.GetDocs().Name, "SplunkCheckFailure", api, core.LogFields{"error": err})
			cancelSplunkSearch()
			continue
		}

		// The first event should be the most recent
		var firstEvent *CVEEvent
		total := 0
		for cveEvent := range cveEvents {
			if firstEvent == nil {
				copy := *cveEvent
				firstEvent = &copy
			}
			csvWriter.Write([]string{cveEvent.Time.String(), cveEvent.CVE, cveEvent.DestinationIP, cveEvent.SourceIP, fmt.Sprintf("%d", cveEvent.DestinationPort), fmt.Sprintf("%d", cveEvent.SourcePort), cveEvent.Alert})
			total++
			if total >= rowLimit {
				csvData.WriteString(fmt.Sprintf("# Results truncated at %d rows", rowLimit))
				break
			}
		}
		if firstEvent != nil {
			triageData.Metadata = append(triageData.Metadata,
				fmt.Sprintf("`%s` was found in *%d*+ splunk alerts in the last *%d* days.  The most recent alert was on *%s* (*%s:%d* -> *%s:%d*) `%s`",
					firstEvent.CVE,
					total,
					recentLoginsBackcheckDays,
					firstEvent.Time.Format("01/02/2006 15:04:05"),
					firstEvent.SourceIP,
					firstEvent.SourcePort,
					firstEvent.DestinationIP,
					firstEvent.DestinationPort,
					firstEvent.Alert,
				))
		}
		cancelSplunkSearch()
	}

	csvWriter.Flush()
	triageData.Data = csvData.String()

	return []*triage.Data{triageData}
}
