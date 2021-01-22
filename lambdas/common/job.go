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
	JobID           string                        `json:"jobID"`
	OriginalRequest events.APIGatewayProxyRequest `json:"original_request"`
}

// CompletedJobData is a set of completed data from a job
type CompletedJobData struct {
	ModuleName string `json:"module_name" dynamodbav:"module_name"`
	JobID      string `json:"job_id" dynamodbav:"job_id"`
	Response   string `json:"response" dynamodbav:"response"`
}

// JobDBEntry is a job entry stored in the database
type JobDBEntry struct {
	JobID string `dynamodbav:"job_id"`
	// Map of module name to the encrypted data
	Responses map[string]appencryption.DataRowRecord `dynamodbav:"responses"`
	Request   appencryption.DataRowRecord            `dynamodbav:"request"`
	// Epoch start time
	StartTime float64 `dynamodbav:"startTime"`
	// Count of total modules that should be run from this request
	TotalModules int `dynamodbav:"totalModules"`

	// Decrypted data
	DecryptedRequest   string
	DecryptedResponses map[string]interface{}
}

// Decrypt will use asherah to decrypt the Responses and Request
func (j *JobDBEntry) Decrypt(ctx context.Context, t *toolbox.Toolbox) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "DecryptJobDBEntry")
	defer span.Finish()

	// Decrypt request
	decryptedData, err := t.Dencrypt(ctx, j.JobID, j.Request)
	if err == nil {
		j.DecryptedRequest = string(decryptedData)
	}

	// Decrypt responses
	j.DecryptedResponses = map[string]interface{}{}
	for moduleName, response := range j.Responses {
		decryptedData, err := t.Dencrypt(ctx, j.JobID, response)
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
}

// JobRequest contains information to request a job to be performed
type JobRequest struct {
	Modules []string `json:"modules"`  // List of modules to run
	IOCs    []string `json:"iocs"`     // List of IOCs
	IOCType string   `json:"ioc_type"` // List of IOCs
}

// GetJobRequest Pulls out the job request from a AWS proxy event
func GetJobRequest(event events.APIGatewayProxyRequest) (JobRequest, error) {
	jobRequest := JobRequest{}
	err := json.Unmarshal([]byte(event.Body), &jobRequest)
	if err != nil {
		return JobRequest{}, err
	}

	return jobRequest, nil
}

// LambdaMetadata is data stored in the parameter store about a specific lambda
type LambdaMetadata struct {
	SupportedIOCTypes []triage.IOCType `json:"supported_ioc_types"`
}
