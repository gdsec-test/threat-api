// Package triagelegacyconnector provides an adapter interface for the legacy triage interface to the new AWS interface
package triagelegacyconnector

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

// AWSToTriage acts as an interface from our new interface to the old threat api triage interface.
// This make it easy to call old triage modules with minimal code changes.
// To do this, this function converts an AWS SNS event to the legacy triage interface, then
// converts the response to what we expect for the response processor.
func AWSToTriage(ctx context.Context, module triage.Module, request events.SNSEvent) ([]*common.CompletedJobData, error) {
	ret := []*common.CompletedJobData{}

	for _, event := range request.Records {
		completedJobData, err := triageSNSEvent(ctx, module, event)
		if err != nil {
			return nil, fmt.Errorf("error processing event: %w", err)
		}
		ret = append(ret, completedJobData)
	}

	return ret, nil
}

// triageSNSEvent converts the aws to legacy interface for a single job
func triageSNSEvent(ctx context.Context, module triage.Module, request events.SNSEventRecord) (*common.CompletedJobData, error) {
	// Unmarshal the SNS job message
	jobMessage := common.JobSNSMessage{}
	err := json.Unmarshal([]byte(request.SNS.Message), &jobMessage)
	if err != nil {
		err = fmt.Errorf("error unmarshaling the SNS message to our common JobMessage structure: %w", err)
		return nil, err
	}

	response := &common.CompletedJobData{
		ModuleName: module.GetDocs().Name,
		JobID:      jobMessage.JobID,
		Response:   "",
	}

	// Pull the job request from the raw request
	jobRequest, err := common.GetJobRequest(jobMessage.OriginalRequest)
	if err != nil {
		err = fmt.Errorf("failed to unmarshal job request: %w", err)
		return nil, err
	}

	// Check if our module should be run
	ourModuleMentioned := func() bool {
		for _, moduleName := range jobRequest.Modules {
			if moduleName == response.ModuleName {
				return true
			}
		}
		return false
	}
	// Check if our module supports the IOC type
	weSupportThisIOCType := func() bool {
		for _, supportedType := range module.Supports() {
			if string(supportedType) == strings.ToLower(jobRequest.IOCType) {
				return true
			}
		}
		return false
	}
	if !ourModuleMentioned() || !weSupportThisIOCType() {
		// TODO: Change this to something else?
		// For now just return nothing
		return response, nil
	}

	// Convert request to triage.TriageRequest
	triageRequest := &triage.Request{
		IOCs: jobRequest.IOCs,
	}

	triageDatas, err := module.Triage(ctx, triageRequest)
	if err != nil {
		err = fmt.Errorf("This module had an error processing this request: %s", err)
		response.Response = err.Error()
		return response, nil
	}

	// Combine the triage data list into a single CompletedJobData.  For now just marshal it
	triageDataMarshal, err := json.Marshal(triageDatas)
	if err != nil {
		err = fmt.Errorf("error marshalling the triage data: %w", err)
		response.Response = err.Error()
		return response, err
	}
	response.Response = string(triageDataMarshal)

	return response, nil
}