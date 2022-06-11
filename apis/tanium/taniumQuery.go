package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"regexp"
	"strings"
	"sync"

	tn "github.com/gdcorp-infosec/threat-api/apis/tanium/taniumLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	maxThreadCount                             = 5
	rowLimit                                   = 100
	host                                       = "https://tanium-dev.int.gdcorp.tools" // will be added to parameter store while cleaning up in next phase
	installedSoftwareQuestion                  = "Get Installed Applications from all machines with Computer Name matches %s"
	computerNamesWithInstalledSoftwareQuestion = "Get Computer Name and Installed Application Version[%s] from all machines with Installed Applications:Name contains %s"
)

// SubmitTaniumQuestion returns the Tanium results for the questions that are queried
func (m *TriageModule) SubmitTaniumQuestion(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	var taniumErr error
	taniumResults := make(map[string]chan tn.Row)

	wg := sync.WaitGroup{}
	taniumLock := sync.Mutex{}
	threadLimit := make(chan int, maxThreadCount)

	for _, ioc := range triageRequest.IOCs {
		// Check context
		select {
		case <-ctx.Done():
			break
		case threadLimit <- 1:
			wg.Add(1)
		default:
		}

		span, spanCtx := tb.TracerLogger.StartSpan(ctx, "TaniumIoCLookup", "tanium", "", "taniumIoCLookup")

		go func(ioc string) {
			defer func() {
				<-threadLimit
				wg.Done()
			}()
			_, taniumResult, err := m.performTaniumSearch(ctx, ioc, triageRequest.IOCsType)
			if err != nil {
				taniumErr = err
				span.AddError(err)
				taniumLock.Lock()
				taniumResults[ioc] = nil
				taniumLock.Unlock()
				return
			}

			taniumLock.Lock()
			taniumResults[ioc] = taniumResult
			taniumLock.Unlock()
			return
		}(ioc)
		span.End(spanCtx)
	}

	wg.Wait()

	triageTaniumData := postProcessing(taniumResults, triageRequest.IOCsType)

	if taniumErr != nil {
		triageTaniumData.Data = fmt.Sprintf("error from tanium: %s", taniumErr)
	}
	return []*triage.Data{triageTaniumData}, taniumErr
}

// performTaniumSearch given a Tanium question, create the question, wait for rowLimit results (or some maximum) to be available in Tanium, and return the column names, a channel of results, and an error if present

func (m *TriageModule) performTaniumSearch(ctx context.Context, ioc string, iocType triage.IOCType) ([]string, chan tn.Row, error) {
	var questionString string

	switch iocType {
	case triage.GoDaddyHostnameType:
		questionString = fmt.Sprintf(installedSoftwareQuestion, ioc)
	case triage.CPEType:
		softwareKeyword := regexp.MustCompile(`(?i)cpe:2[.]3?:[\/]?[aoh*\-]:[a-z0-9\-._]*:([a-z0-9\-._]*):`)
		softwareName := softwareKeyword.FindAllStringSubmatch(ioc, -1)
		fmt.Printf("%v", softwareName[0][1])
		if len(softwareName) == 1 && len(softwareName[0]) == 2 {
			softwareKeyword := softwareName[0][1]
			softwareKeyword = strings.ReplaceAll(softwareKeyword, "_", " ")
			softwareKeyword = strings.ReplaceAll(softwareKeyword, ".", " ")
			questionString = fmt.Sprintf(computerNamesWithInstalledSoftwareQuestion, softwareKeyword, softwareKeyword)
		} else {
			return nil, nil, fmt.Errorf("Cannot extract software name from CPE %s", ioc)
		}
	default:
		return nil, nil, fmt.Errorf("Current IOC Type %s is not supported", iocType)
	}

	c, err := tn.NewTaniumClient(ctx, host)

	parsable, err := c.CanParse(ctx, questionString)
	if err != nil {
		return nil, nil, err
	} else if !parsable {
		return nil, nil, fmt.Errorf("question not parsable")
	}

	question, err := c.CreateQuestion(ctx, questionString)
	if err != nil {
		return nil, nil, err
	}

	cols, err := question.GetColumns(context.Background())
	if err != nil {
		return nil, nil, err
	}

	columns := make([]string, 0)

	// Get the names of all columns from the Tanium question
	for _, b := range cols {
		columns = append(columns, b.Name)
	}

	err = question.WaitForResults(ctx, rowLimit)
	if err != nil {
		return nil, nil, err
	}

	results, err := question.GetResults(ctx)
	if err != nil {
		return nil, nil, err
	}

	return columns, results, nil

}

//postProcessing calculates the CSV and metadata for Godaddy hostnames
func postProcessing(taniumResults map[string]chan tn.Row, iocType triage.IOCType) *triage.Data {
	//For dumping data as csv
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)

	//MetaData is being calculated here as the results are in a channel, so they can be read out once.
	//Instead of creating a duplicate channel and calculating the metadata it's more optimal doing both while reading the original returned channel

	//MetaData gathering
	var machinesMetadata []string
	triageTaniumMachineData := &triage.Data{
		Metadata: []string{},
	}
	metadataCounter := ""
	switch iocType {
	case triage.GoDaddyHostnameType:
		// Write headers
		csv.Write([]string{
			"Machine Name",
			"Data",
		})
		triageTaniumMachineData.Title = "Programs and versions installed in the queried machine"
		metadataCounter = "*%s* has *%d* programs installed"
	case triage.CPEType:
		// Write headers
		csv.Write([]string{
			"CPE",
			"Data",
		})
		triageTaniumMachineData.Title = "Machines which have installed software found in CPE"
		metadataCounter = "CPE *%s* has *%d* machines found with installed software"
	}

	for ioc, row := range taniumResults {
		count := 0 // Count for keeping track of the metadata

		if row == nil {
			continue
		}

		var rowOutputData string

		for data := range row {
			count++
			for _, r := range data.Data {
				rowOutputData = rowOutputData + " " + r.String()
			}
		}

		machinesMetadata = append(machinesMetadata, fmt.Sprintf(metadataCounter, ioc, count))

		cols := []string{
			ioc,
			rowOutputData,
		}
		csv.Write(cols)

	}
	csv.Flush()

	triageTaniumMachineData.DataType = triage.CSVType
	triageTaniumMachineData.Data, triageTaniumMachineData.Metadata = resp.String(), machinesMetadata

	return triageTaniumMachineData
}
