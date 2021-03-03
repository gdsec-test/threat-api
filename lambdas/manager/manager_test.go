package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	testBody = `{"metadata":{"name":"test"}}`
)

// Test creating a job in the DB.
// This test required a TESTING_JWT and valid AWS credentials.
func TestJobWork(t *testing.T) {
	testingJWT := os.Getenv("TESTING_JWT")
	headers := map[string]string{"cookie": fmt.Sprintf("auth_jomax=%s", testingJWT)}

	// Only perform this test if we are working locally, not in CICD
	// In the future we can enable this test when we get a testing JWT
	if os.Getenv("PERFORM_REAL_TESTS") == "" {
		t.Skip("Not running test")
		return
	}

	var jobID string
	t.Run("CreateJob", func(t *testing.T) {
		// Create an empty job
		resp, err := handler(context.Background(), events.APIGatewayProxyRequest{
			Headers:    headers,
			Body:       testBody,
			Path:       version + "/jobs",
			HTTPMethod: "POST",
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("bad response code: %d", resp.StatusCode)
		}

		// Check to make sure we got our JobID
		response := struct {
			JobID string `json:"jobId"`
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
			Path:           version + "/jobs/",
			PathParameters: map[string]string{jobIDKey: jobID},
			HTTPMethod:     http.MethodGet,
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("bad response code: %d", resp.StatusCode)
		}

		// Check to make sure we got our JobID
		response := struct {
			common.JobDBEntry
			JobStatus     JobStatus `json:"jobStatus"`
			JobPercentage float64   `json:"jobPercentage"`
		}{}
		err = json.Unmarshal([]byte(resp.Body), &response)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("Found job data: %v\n", response)
		if string(response.JobStatus) == string(JobCompleted) {
			fmt.Println("WARN: Job is already completed, that was quick")
		}

		// Make sure we got back our original request
		submissionBytes, _ := json.Marshal(response.DecryptedSubmission)
		if string(submissionBytes) != testBody {
			t.Errorf("did not get original request/submission we made (was it not decrypted correctly?). Expected %s got %s", testBody, string(submissionBytes))
		}

		// Check to make sure TotalModules > 0
		if response.TotalModules == 0 {
			t.Errorf("Returned 0 total modules, probably expecting this to be more than 0")
		}

		// Wait a bit and check if the job completed
		time.Sleep(time.Second * 3)
		resp, err = handler(context.Background(), events.APIGatewayProxyRequest{
			Path:           version + "/jobs/",
			PathParameters: map[string]string{jobIDKey: jobID},
			HTTPMethod:     http.MethodGet,
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("bad response code: %d", resp.StatusCode)
		}
		err = json.Unmarshal([]byte(resp.Body), &response)
		if err != nil {
			t.Fatal(err)
		}
		if string(response.JobStatus) != string(JobCompleted) {
			t.Errorf("job did not complete, it is in state %s", response.JobStatus)
		}
		if response.JobPercentage == 0 {
			t.Error("Job percentage stuck at 0%, there's probably a problem generating the percentage, or no responses were generated.")
		}

		fmt.Printf("Found job data after waiting: %v\n", response)
	})

	t.Run("GetJobs", func(t *testing.T) {
		// Get the jobs of this user
		resp, err := handler(context.Background(), events.APIGatewayProxyRequest{
			Path:       version + "/jobs/",
			Headers:    headers,
			HTTPMethod: http.MethodGet,
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("bad response code: %d", resp.StatusCode)
		}

		// Check to make sure we got our JobID
		response := []common.JobDBEntry{}
		err = json.Unmarshal([]byte(resp.Body), &response)
		if err != nil {
			t.Fatal(err)
		}
		findOurJob := func() *common.JobDBEntry {
			for _, job := range response {
				if job.JobID == jobID {
					j := job
					return &j
				}
			}
			return nil
		}
		ourJob := findOurJob()
		if ourJob == nil {
			t.Errorf("did not find our jobID %s in returned jobIDs %v", jobID, response)
		}
		if _, ok := ourJob.DecryptedSubmission["metadata"]; !ok {
			t.Errorf("metadata not returned for our job in the jobs list")
		}

		// Make sure submission and responses (unencrypted) are not populated
		if ourJob.Responses != nil {
			t.Errorf("There are unencrypted responses in the returned data for fetching jobs and it shouldn't be")
		}
		if len(ourJob.Submission.Data) != 0 {
			t.Errorf("The unencrypted request/submission is in the returned data for fetching jobs and it shouldn't be")
		}

		fmt.Printf("Found user's jobs: %v\n", response)
	})

	t.Run("DeleteJob", func(t *testing.T) {
		// Get the created job
		resp, err := handler(context.Background(), events.APIGatewayProxyRequest{
			Path:           version + "/jobs/",
			PathParameters: map[string]string{jobIDKey: jobID},
			Headers:        headers,
			HTTPMethod:     "DELETE",
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("bad response code: %d", resp.StatusCode)
		}

		// Check if job is actually deleted
		resp, err = handler(context.Background(), events.APIGatewayProxyRequest{
			Path:           version + "/jobs/",
			PathParameters: map[string]string{jobIDKey: jobID},
			HTTPMethod:     http.MethodGet,
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Expected status code 404 but got: %d", resp.StatusCode)
		}

	})
	to.Close(context.Background())
}

func TestClassifyIOCs(t *testing.T) {
	resp, err := handler(context.Background(), events.APIGatewayProxyRequest{
		Path:       version + "/classifications",
		HTTPMethod: "POST",
		Body:       `{"iocs":["1.1.1.1","domain.com","email@email.com"]}`,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 200 {
		t.Fatalf("bad error code: %d body: %s", resp.StatusCode, resp.Body)
	}

	// Check if the response is what we expect
	expectedResponse := map[triage.IOCType][]string{
		triage.DomainType: {"domain.com"},
		triage.EmailType:  {"email@email.com"},
		triage.IPType:     {"1.1.1.1"},
	}
	actualResponse := map[triage.IOCType][]string{}

	err = json.Unmarshal([]byte(resp.Body), &actualResponse)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expectedResponse, actualResponse) {
		t.Errorf("Did not get expected result")
	}
}

func TestGetModulesRequest(t *testing.T) {
	resp, err := handler(context.Background(), events.APIGatewayProxyRequest{
		Path:       version + "/modules",
		HTTPMethod: "GET",
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 200 {
		t.Fatalf("bad error code: %d body: %s", resp.StatusCode, resp.Body)
	}

	ret := map[string]toolbox.LambdaMetadata{}
	err = json.Unmarshal([]byte(resp.Body), &ret)
	if err != nil {
		t.Fatal(err)
	}

	if len(ret) == 0 {
		t.Fatalf("no results returned")
	}
}
