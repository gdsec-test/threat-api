// Package common provides some common data structures shared accross lambdas
package common

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-lambda-go/events"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/godaddy/asherah/go/appencryption"
)

// JobSNSMessage is the structure sent via the SNS topic to represent a job ready for processing
type JobSNSMessage struct {
	JobID      string                        `json:"jobId"`
	Submission events.APIGatewayProxyRequest `json:"submission"`
}

// CompletedJobData is a set of completed data from a job.
// This is the data we expect each lambda to output when it completes.
type CompletedJobData struct {
	ModuleName string `json:"module_name" dynamodbav:"module_name"`
	JobID      string `json:"jobId" dynamodbav:"jobId"`
	Response   string `json:"response" dynamodbav:"response"`
}

// JobDBEntry is a job entry stored in the database.
// This is also used as the standard structure to return to API responses
type JobDBEntry struct {
	JobID string `dynamodbav:"jobId" json:"jobId"`
	// Map of module name to the encrypted data
	Responses  map[string]appencryption.DataRowRecord `dynamodbav:"responses" json:"-"`
	Submission appencryption.DataRowRecord            `dynamodbav:"submission" json:"-"`
	// Epoch start time
	StartTime float64 `dynamodbav:"startTime" json:"startTime"`
	// Count of total modules that should be run from this submission
	TotalModules int `dynamodbav:"totalModules" json:"totalModules"`

	// Decrypted data
	// The ignore tags in dynamodbav are to prevent the json tags
	// from stealing the elements from Submission and Response (unencrypted values)
	DecryptedSubmission map[string]interface{} `dynamodbav:"-" json:"submission"`
	DecryptedResponses  map[string]interface{} `dynamodbav:"-" json:"responses"`
}

// Decrypt will use asherah to decrypt the Responses and Submission
func (j *JobDBEntry) Decrypt(ctx context.Context, t *toolbox.Toolbox) {
	span, ctx := t.TracerLogger.StartSpan(ctx, "DecryptJobDBEntry", "job", "db", "decrypt")
	defer span.End(ctx)

	// Decrypt submission
	span, ctx = t.TracerLogger.StartSpan(ctx, "DecryptSubmission", "job", "submission", "decrypt")
	decryptedData, err := t.Decrypt(ctx, j.JobID, j.Submission)
	if err == nil {
		json.Unmarshal(decryptedData, &j.DecryptedSubmission)
	}
	span.End(ctx)

	// Decrypt responses
	span, ctx = t.TracerLogger.StartSpan(ctx, "DecryptResponses", "job", "responses", "decrypt")
	j.DecryptedResponses = map[string]interface{}{}
	for moduleName, response := range j.Responses {
		decryptedData, err := t.Decrypt(ctx, j.JobID, response)
		if err != nil {
			continue
		}
		// Try to unmarshal the response data
		var unmarshalledDecryptedData interface{}
		err = json.Unmarshal(decryptedData, &unmarshalledDecryptedData)
		if err != nil {
			// Just put the string version if we cannot unmarshal it
			j.DecryptedResponses[moduleName] = string(decryptedData)
			continue
		}
		j.DecryptedResponses[moduleName] = unmarshalledDecryptedData
	}
	span.End(ctx)
}

// JobSubmission contains information to request a job to be performed
type JobSubmission struct {
	Modules []string `json:"modules"` // List of modules to run
	IOCs    []string `json:"iocs"`    // List of IOCs
	IOCType string   `json:"iocType"`
}

// GetJobSubmission Pulls out the job submission from a AWS proxy event
func GetJobSubmission(event events.APIGatewayProxyRequest) (JobSubmission, error) {
	jobSubmission := JobSubmission{}
	err := json.Unmarshal([]byte(event.Body), &jobSubmission)
	if err != nil {
		return JobSubmission{}, err
	}

	return jobSubmission, nil
}
