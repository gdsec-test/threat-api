package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"sync"

	servicenow "github.com/gdcorp-infosec/threat-api/apis/servicenow/servicenowLibrary"
)

const (
	maxTableThreads = 3
)

// HostNameCMDBData contains just the data to pull out for processing
type HostNameCMDBData struct {
	AssignmentGroup []string
	SupportGroup    []string
}

// GetCMDBData returns the data from CMDB - currently support group and assignment group
func (m *TriageModule) GetCMDBData(ctx context.Context, IOCs []string) (map[string]*HostNameCMDBData, error) {
	cmdbResults := make(map[string]*HostNameCMDBData)

	newClient, err := servicenow.NewFromConfig(&m.SNClient.Config, "cmdb_ci")
	if err != nil {
		return nil, err
	}

	wg := sync.WaitGroup{}
	cmdbLock := sync.Mutex{}
	// Limit the number of concurrent IOCs to scan for in the table
	threadLimit := make(chan int, maxTableThreads)

	for _, ioc := range IOCs {
		// Check if a thread is available
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil, ctx.Err()
		case threadLimit <- 1:
			wg.Add(1)
		default:
		}

		span, spanCtx := tb.TracerLogger.StartSpan(ctx, "SNHostnameLookup", "servicenow", "cmdb", "hostnameEnrich")

		go func(ioc string) {
			rows := make(chan servicenow.Row)
			ctxInner, cancel := context.WithCancel(ctx)
			defer func() {
				<-threadLimit
				wg.Done()
				cancel()
			}()
			// Spawn thread to scan the table
			go func(ioc string) {
				// set the ioc as fully qualified domain name
				query := fmt.Sprintf("fqdn=%s", ioc)

				//set additional values - currently retrieving only assignment group and support group
				additionalURLValues := url.Values{
					"sysparm_fields": []string{"assignment_group,support_group"},
				}
				// Perform search
				err := newClient.GetRows(ctxInner, query, additionalURLValues, rows)
				if err != nil {
					span.AddError(err)
					cmdbLock.Lock()
					cmdbResults[ioc] = nil
					cmdbLock.Unlock()
				}
			}(ioc)

			// For every row returned, its groups associated - either support or assignment
			var assignmentGroups, supportGroups []string
			for row := range rows {
				//extract assignment group name
				if groupData, ok := row["assignment_group"]; ok {
					// when there is data- its a map, else its a string[assignment_group]. Checking on data availability
					if reflect.TypeOf(groupData).Kind() == reflect.Map {
						assignGroupName, err := m.extractGroupName(ctxInner, groupData)
						if err != nil {
							span.AddError(err)
						} else {
							assignmentGroups = append(assignmentGroups, assignGroupName)
						}
					}
				}

				//extract support group name
				if groupData, ok := row["support_group"]; ok {
					// when there is data its a map, else its a string[support_group]. Checking on data availability
					if reflect.TypeOf(groupData).Kind() == reflect.Map {
						supportGroupName, err := m.extractGroupName(ctxInner, groupData)
						if err != nil {
							span.AddError(err)
						} else {
							supportGroups = append(supportGroups, supportGroupName)
						}
					}
				}
			}

			// Assign the groups back to return data
			cmdbLock.Lock()
			cmdbResults[ioc] = &HostNameCMDBData{
				AssignmentGroup: assignmentGroups,
				SupportGroup:    supportGroups,
			}
			cmdbLock.Unlock()

		}(ioc)
		span.End(spanCtx)
	}
	wg.Wait()

	return cmdbResults, nil
}

// extractGroupName returns 'named' groups from the Id's returned from cmdb_ci table call
func (m *TriageModule) extractGroupName(ctx context.Context, groupData interface{}) (string, error) {
	sysID := groupData.(map[string]interface{})["value"].(string)

	paramValues := url.Values{
		"sysparm_fields": []string{"name"},
	}

	// setting the table name - 'sys_user_group'
	newSnowConfig := m.SNClient.Config
	client, err := servicenow.NewFromConfig(&newSnowConfig, "sys_user_group")
	if err != nil {
		return "", err
	}

	row, err := client.GetUniqueRow(ctx, sysID, "", paramValues)
	if err != nil {
		return "", err
	}

	// extract name from row returned
	nameMap, ok := row["result"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("casting errors")
	}
	return (nameMap["name"]).(string), nil
}

//dumpCSV dumps the triage data to CSV
func dumpCSV(servicenowResults map[string]*HostNameCMDBData) string {
	//Dump data as csv
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)
	// Write headers
	csv.Write([]string{
		"IoC",
		"Assignment Groups",
		"Support Groups",
	})
	for ioc, data := range servicenowResults {
		if data == nil {
			continue
		}

		cols := []string{
			// TODO: Convert your datatype  to string
			ioc,
			strings.Join(data.SupportGroup, " /"),
			strings.Join(data.AssignmentGroup, " /"),
		}
		csv.Write(cols)

	}
	csv.Flush()

	return resp.String()
}
