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
			t.Fatal(err)
			return
		}

		// Check to make sure we got our JobID
		response := Response{}
		err = json.Unmarshal([]byte(resp.Body), &response)
		if err != nil {
			t.Fatal(err)
			return
		}
		if response.Error != "" {
			t.Fatal(err)
			return
		}
		if len(response.JobIDs) == 0 {
			t.Fatal("no job IDs returned")
			return
		}
		jobID = response.JobIDs[0]
		fmt.Printf("Created job ID: %v\n", response.JobIDs)
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
			t.Error(response.Error)
			return
		}
		fmt.Printf("Found job data: %v\n", response.Data)
	})

	t.Run("GetJobs", func(t *testing.T) {
		// Get the jobs of this user
		resp, err := handler(context.Background(), events.APIGatewayProxyRequest{
			Path: "/jobs/",
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
		if len(response.JobIDs) != 1 || response.JobIDs[0] != jobID {
			t.Errorf("Did not get expected job ids for user, we got %v but expected %s", response.JobIDs, jobID)
		}

		// TODO: Make sure we only go the job we just created
		fmt.Printf("Found user's jobs: %v\n", response.JobIDs)
	})
}
