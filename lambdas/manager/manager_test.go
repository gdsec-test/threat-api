package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

const (
	testBody = `{"test":"test"}`
)

// Test creating a job in the DB
func TestJobWork(t *testing.T) {
	testingJWT := os.Getenv("TESTING_JWT")
	headers := map[string]string{"cookie": fmt.Sprintf("auth_jomax=%s", testingJWT)}

	var jobID string
	t.Run("CreateJob", func(t *testing.T) {
		// Create an empty job
		resp, err := handler(context.Background(), events.APIGatewayProxyRequest{
			Headers: headers,
			Body:    testBody,
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("bad response code: %d", resp.StatusCode)
		}

		// Check to make sure we got our JobID
		response := struct {
			JobID string `json:"job_id"`
		}{}
		err = json.Unmarshal([]byte(resp.Body), &response)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("Created job ID: %v\n", response.JobID)
		jobID = response.JobID
	})

	if jobID == "" {
		t.FailNow()
	}

	t.Run("GetJob", func(t *testing.T) {
		// Get the job status
		resp, err := handler(context.Background(), events.APIGatewayProxyRequest{
			PathParameters: map[string]string{"job_id": jobID},
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("bad response code: %d", resp.StatusCode)
		}

		// Check to make sure we got our JobID
		var response map[string]interface{}
		err = json.Unmarshal([]byte(resp.Body), &response)
		if err != nil {
			t.Fatal(err)
		}

		// Make sure we got back our original request
		if response["request"] != testBody {
			t.Errorf("did not get original request we made (must not have been decrypted correctly). Expected %s got %s", testBody, response["request"])
		}

		fmt.Printf("Found job data: %v\n", response)
	})

	t.Run("GetJobs", func(t *testing.T) {
		// Get the jobs of this user
		resp, err := handler(context.Background(), events.APIGatewayProxyRequest{
			Path:    "/jobs/",
			Headers: headers,
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("bad response code: %d", resp.StatusCode)
		}

		// Check to make sure we got our JobID
		response := []string{}
		err = json.Unmarshal([]byte(resp.Body), &response)
		if err != nil {
			t.Fatal(err)
		}
		foundOurJob := func() bool {
			for _, jID := range response {
				if jID == jobID {
					return true
				}
			}
			return false
		}
		if !foundOurJob() {
			t.Errorf("did not find our jobID %s in returned jobIDs %v", jobID, response)
		}

		fmt.Printf("Found user's jobs: %v\n", response)
	})
}
