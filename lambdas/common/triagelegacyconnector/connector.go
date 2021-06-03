// Package triagelegacyconnector provides an adapter interface for the legacy triage interface to the new AWS interface
package triagelegacyconnector

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	// This limit sets the time limit for an old module before canceling it's context.
	// The previous framework operated such that each module could run as long as it wants,
	// until the parent cancels the context.  Then the module would wrap up and send whatever
	// results it has.  Because we now operate in lambdas, we need to cancel the lambda slightly
	// before the lambda timeout so it can return partial results.
	// For now this is hard coded to 5 minutes.
	moduleTimeLimit = time.Minute * 5
)

// AWSToTriage acts as an interface from our new interface to the old threat api triage interface.
// This make it easy to call old triage modules with minimal code changes.
// To do this, this function converts an AWS SNS event to the legacy triage interface, then
// converts the response to what we expect for the response processor.
func AWSToTriage(ctx context.Context, t *toolbox.Toolbox, module triage.Module, request events.SNSEvent) ([]*common.CompletedJobData, error) {
	ret := []*common.CompletedJobData{}

	// Start each job in a new thread
	wg := sync.WaitGroup{}
	jobErrors := make(chan error) // Channel to capture any error
	jobsCtx, jobsCancel := context.WithCancel(ctx)
	for _, event := range request.Records {
		wg.Add(1)
		// Spawn thread to handle this job
		go func(event events.SNSEventRecord) {
			defer wg.Done()

			completedJobData, err := triageSNSEvent(jobsCtx, t, module, event)
			if completedJobData != nil {
				ret = append(ret, completedJobData)
			}
			if err != nil {
				// Alert the other thread about this error to cancel everything
				jobErrors <- fmt.Errorf("error processing event: %w", err)
				return
			}
			// TODO: check if the returned data is too large for SNS, and therefore needs to be put in a S3 or something.

		}(event)
	}

	// Start thread to wait for all jobs to be done
	allJobsDone := make(chan struct{})
	go func() {
		// block until the WaitGroup counter goes back to 0
		wg.Wait()
		// Signal that all jobs are done, or if we are
		// dealing with a different scenario, do nothing so this go routine
		// doesn't dangle around.
		select {
		case allJobsDone <- struct{}{}:
		default:
		}
	}()

	// Wait for either each job to finish, or time to run out!
	select {
	case jobError := <-jobErrors: // A job had an error, cancel everything and return the error
		jobsCancel()
		wg.Wait()

		return nil, jobError
	case <-time.After(moduleTimeLimit): // Out of time!  We need to wrap up!
		// Cancel the context, this should cause all jobs to "wrap up"
		// and return partial results (see the comments on the module.Triage interface)
		jobsCancel()
		// Wait for the job(s) to actually finish
		wg.Wait()
	case <-allJobsDone: // We are all done :)
	}
	jobsCancel()
	return ret, nil
}

// triageSNSEvent converts the aws to legacy interface for a single job
func triageSNSEvent(ctx context.Context, t *toolbox.Toolbox, module triage.Module, request events.SNSEventRecord) (*common.CompletedJobData, error) {
	span, spanCtx := t.TracerLogger.StartSpan(ctx, "TriageLegacyConnector", "triagelegacyconnector", "sns", "triage")
	defer span.End(spanCtx)

	// Unmarshal the SNS job message
	jobMessage := common.JobSNSMessage{}
	err := json.Unmarshal([]byte(request.SNS.Message), &jobMessage)
	if err != nil {
		err = fmt.Errorf("error unmarshaling the SNS message to our common JobMessage structure: %w", err)
		span.AddError(err)
		return nil, err
	}

	// Pull out the JWT to pass to triage request
	JWT := toolbox.GetJWTFromRequest(jobMessage.Submission)
	span.LogKV("JWTLength", len(JWT))

	response := &common.CompletedJobData{
		ModuleName: module.GetDocs().Name,
		JobID:      jobMessage.JobID,
		Response:   "",
	}

	// Pull the job submission from the raw request
	jobSubmission, err := common.GetJobSubmission(jobMessage.Submission)
	if err != nil {
		err = fmt.Errorf("failed to unmarshal job submission: %w", err)
		return nil, err
	}
	fmt.Printf("Got job submission: %v\n", jobSubmission)
	span.LogKV("IOCType", jobSubmission.IOCType)
	span.LogKV("IOCsLength", len(jobSubmission.IOCs))

	// Check if our module should be run
	ourModuleMentioned := func() bool {
		for _, moduleName := range jobSubmission.Modules {
			if moduleName == response.ModuleName {
				return true
			}
		}
		return false
	}
	// Check if our module supports the IOC type
	weSupportThisIOCType := func() bool {
		for _, supportedType := range module.Supports() {
			if strings.ToLower(string(supportedType)) == strings.ToLower(jobSubmission.IOCType) {
				return true
			}
		}
		return false
	}
	ourModuleMentionedOut := ourModuleMentioned()
	weSupportThisIOCTypeOut := weSupportThisIOCType()
	span.LogKV("ourModuleMentioned", ourModuleMentionedOut)
	span.LogKV("weSupportThisIOC", weSupportThisIOCTypeOut)
	if !ourModuleMentionedOut || !weSupportThisIOCTypeOut {
		fmt.Printf("Not processing, mentioned %v, support this IOC type: %v\n", ourModuleMentionedOut, weSupportThisIOCTypeOut)
		return nil, nil
	}

	// Convert request to triage.TriageRequest
	triageRequest := &triage.Request{
		IOCs:     jobSubmission.IOCs,
		IOCsType: triage.IOCType(strings.ToUpper(jobSubmission.IOCType)),
		JWT:      JWT,
	}

	spanExecute, spanExecuteCtx := t.TracerLogger.StartSpan(spanCtx, "Execute", "module", "", "execute")
	defer spanExecute.End(spanExecuteCtx)
	spanExecute.LogKV("moduleName", module.GetDocs().Name)
	spanExecute.LogKV("jobID", jobMessage.JobID)
	spanExecute.LogKV("iocType", jobSubmission.IOCType)

	triageDatas, err := module.Triage(ctx, triageRequest)
	if err != nil {
		err = fmt.Errorf("this module had an error processing this request: %s", err)
		span.AddError(err)
		response.Response = err.Error()
		return nil, err
	}

	// Combine the triage data list into a single CompletedJobData.  For now just marshal it
	triageDataMarshal, err := json.Marshal(triageDatas)
	if err != nil {
		err = fmt.Errorf("error marshalling the triage data: %w", err)
		response.Response = err.Error()
		span.AddError(err)
		return nil, err
	}
	response.Response = string(triageDataMarshal)

	return response, nil
}
