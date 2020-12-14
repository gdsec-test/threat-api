package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

// Test creating a job in the DB
func TestCreateJob(t *testing.T) {
	var jobID string
	t.Run("CreateJob", func(t *testing.T) {
		// Create an empty job
		resp, err := handler(context.Background(), events.APIGatewayProxyRequest{})
		if err != nil {
			t.Error(err)
			return
		}

		// Check to make sure we got our JobID
		response := Response{}
		err = json.Unmarshal([]byte(resp.Body), &response)
		if err != nil {
			t.Error(err)
			return
		}
		if response.Error != "" {
			t.Error(err)
			return
		}
		jobID = response.JobID
		fmt.Printf("Got job ID: %s\n", response.JobID)
	})

	t.Run("GetJob", func(t *testing.T) {
		// Get the job status
		resp, err := handler(context.Background(), events.APIGatewayProxyRequest{
			PathParameters: map[string]string{"job_id": jobID},
		})
		if err != nil {
			t.Error(err)
			return
		}

		// Check to make sure we got our JobID
		response := Response{}
		err = json.Unmarshal([]byte(resp.Body), &response)
		if err != nil {
			t.Error(err)
			return
		}
		if response.Error != "" {
			t.Error(err)
			return
		}
		fmt.Printf("Found job data: %v\n", response.Data)
	})
}
