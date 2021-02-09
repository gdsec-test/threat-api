// Package common provides some common data structures shared accross lambdas
package common

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-lambda-go/events"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
	"github.com/gdcorp-infosec/threat-util/lambda/toolbox"
	"github.com/godaddy/asherah/go/appencryption"
	"github.com/opentracing/opentracing-go"
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
	JobID string `dynamodbav:"jobId"`
	// Map of module name to the encrypted data
	Responses  map[string]appencryption.DataRowRecord `dynamodbav:"responses" json:"-"`
	Submission appencryption.DataRowRecord            `dynamodbav:"submission" json:"-"`
	// Epoch start time
	StartTime float64 `dynamodbav:"startTime" json:"StartTime"`
	// Count of total modules that should be run from this submission
	TotalModules int `dynamodbav:"totalModules" json:"TotalModules"`

	// Decrypted data
	// The ignore tags in dynamodbav are to prevent the json tags
	// from stealing the elements from Submission and Response (unencrypted values)
	DecryptedSubmission map[string]interface{} `dynamodbav:"-" json:"submission"`
	DecryptedResponses  map[string]interface{} `dynamodbav:"-" json:"responses"`
}

// Decrypt will use asherah to decrypt the Responses and Submission
func (j *JobDBEntry) Decrypt(ctx context.Context, t *toolbox.Toolbox) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "DecryptJobDBEntry")
	defer span.Finish()

	// Decrypt submission
	span, ctx = opentracing.StartSpanFromContext(ctx, "DecryptSubmission")
	decryptedData, err := t.Decrypt(ctx, j.JobID, j.Submission)
	if err == nil {
		json.Unmarshal(decryptedData, &j.DecryptedSubmission)
	}
	span.Finish()

	// Decrypt responses
	span, ctx = opentracing.StartSpanFromContext(ctx, "DecryptResponses")
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
	span.Finish()
}

// JobSubmission contains information to request a job to be performed
type JobSubmission struct {
	Modules []string `json:"modules"` // List of modules to run
	IOCs    []string `json:"iocs"`    // List of IOCs
	IOCType string   `json:"iocType"` // List of IOCs
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

// LambdaMetadata is data stored in the parameter store about a specific lambda
type LambdaMetadata struct {
	SupportedIOCTypes []triage.IOCType `json:"supportedIOCTypes"`
}
