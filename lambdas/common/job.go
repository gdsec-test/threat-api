// Package common provides some common data structures shared accross lambdas
package common

import (
	"context"

	"github.com/aws/aws-lambda-go/events"
	"github.com/godaddy/asherah/go/appencryption"
	"github.com/opentracing/opentracing-go"
	"github.secureserver.net/threat/util/lambda/toolbox"
)

// JobMessage is the structure sent via the SNS topic to represent a job ready for processing
type JobMessage struct {
	JobID           string                        `json:"jobID"`
	OriginalRequest events.APIGatewayProxyRequest `json:"original_request"`
}

// CompletedJobData is a set of completed data from a job
type CompletedJobData struct {
	JobID      string `json:"job_id" dynamodbav:"job_id"`
	ModuleName string `json:"module_name" dynamodbav:"module_name"`
	Response   string `json:"response" dynamodbav:"response"`
}

// JobDBEntry is a job entry stored in the database
type JobDBEntry struct {
	JobID string `dynamodbav:"job_id"`
	// Map of module name to the encrypted data
	Responses map[string]appencryption.DataRowRecord `dynamodbav:"responses"`
	Request   appencryption.DataRowRecord            `dynamodbav:"request"`
	StartTime interface{}                            `dynamodbav:"startTime"`

	// Decrypted data
	DecryptedRequest   string
	DecryptedResponses map[string]string
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
	j.DecryptedResponses = map[string]string{}
	for moduleName, response := range j.Responses {
		decryptedData, err := t.Dencrypt(ctx, j.JobID, response)
		if err == nil {
			j.DecryptedResponses[moduleName] = string(decryptedData)
		}
	}
}
