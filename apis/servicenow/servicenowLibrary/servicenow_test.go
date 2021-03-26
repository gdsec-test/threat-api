package servicenowLibrary

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// testingClient is a helper function to reliably create a client for testing in a real environment
func testingClient() (*Client, error) {
	return New(os.Getenv("SNOW_TEST_URL"), os.Getenv("SNOW_TEST_USERNAME"), os.Getenv("SNOW_TEST_PASSWORD"), os.Getenv("SNOW_TEST_TABLE"))
}

func TestCreateTicket(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(rw http.ResponseWriter, req *http.Request) {
			if req.URL.String() == "/api/now/v1/table/tableName" {
				message := `{"result":{"sys_id":"b9ed1340db0233000514fe1b68961949","u_number":"SEC0010046"}}`
				rw.WriteHeader(http.StatusCreated)
				rw.Write([]byte(message))
			} else if req.URL.String() == "/api/now/v1/attachment/file?file_name=testingfiles&table_name=tableName&table_sys_id=b9ed1340db0233000514fe1b68961949" {
				rw.WriteHeader(http.StatusCreated)
				rw.Write([]byte(`File uploaded`))
			} else if req.URL.String() == "/api/now/v1/table/tableName/b9ed1340db0233000514fe1b68961949?sysparm_exclude_ref_link=true" {
				rw.WriteHeader(http.StatusOK)
				rw.Write([]byte(`Ticket edited`))
			} else if req.URL.String() == "/api/now/v1/table/tableName?u_number=SEC0010046" {
				message := `{"result":[{"sys_id":"b9ed1340db0233000514fe1b68961949"}]}`
				rw.WriteHeader(http.StatusOK)
				rw.Write([]byte(message))
			}

		}))
	defer server.Close()

	c, err := New(server.URL, "username", "password", "tableName")
	if err != nil {
		t.Fatalf("error in creating the credential context: %s", err)
	}

	ctx := context.TODO()
	body := Body{
		State:   "New",
		Title:   "ThreatAPI client test",
		Summary: "ThreatAPI client to create incident on ServiceNow"}
	fileMap := make(map[string][]byte)
	fileMap["testingfiles"] = []byte(`ok`)

	ticket, err := c.CreateTicket(ctx, &body, fileMap, true)
	if err != nil {
		t.Fatalf("error in creating the ticket: %s", err)
	}

	err = c.AppendToSnowTicketWorklogWithSysId(ctx, "b9ed1340db0233000514fe1b68961949", "Test data for sys_id")
	if err != nil {
		t.Fatalf("error in appending to the ticket with sys_id: %s", err)
	}

	err = c.AppendToSnowTicketWorklog(ctx, "SEC0010046", "Test data for ticket number")
	if err != nil {
		t.Fatalf("error in appending to the ticket with ticket number: %s", err)
	}

	if ticket.SysID != "b9ed1340db0233000514fe1b68961949" {
		t.Fatalf("test failed on sys id mismatch")
	} else if ticket.Number != "SEC0010046" {
		t.Fatalf("test failed on ticket number mismatch")
	} else if len(ticket.Warnings) != 0 {
		t.Fatalf("test failed on length of warnings mismatch")
	} else if ticket.HasWarnings() != false {
		t.Fatalf("test failed on HasWarnings() method return type mismatch")
	}
}

// TestGetTicketsReal Runs a test against the godaddy dev snow environment
func TestGetTicketsReal(t *testing.T) {
	// This test is not complete
	c, err := testingClient()
	if err != nil {
		t.Error(err)
	}

	ticket, err := c.CreateTicket(context.Background(), &Body{
		State:           "new",
		Impact:          "2",
		Urgency:         "2",
		Title:           "Test ticket",
		AssignmentGroup: "Eng-ThreatIntel",
	}, nil, true)
	if err != nil {
		t.Error(err)
		return
	}

	fmt.Println(ticket.Number)
	fmt.Println(ticket.SysID)
}

func TestGetAllRows(t *testing.T) {
	startTime := time.Now()
	c, err := testingClient()
	if err != nil {
		t.Error(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	rows := make(chan Row)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		err := c.GetRows(ctx, "", nil, rows)
		if err != nil && !strings.Contains(err.Error(), "context cancelled") {
			t.Error(err)
		}
		wg.Done()
	}()

	goal := 4005

	// Read a single row
	totalFound := 0
	for range rows {
		totalFound++
		if totalFound >= goal {
			break
		}
	}
	cancel()
	// Wait for processing to actually stop
	wg.Wait()
	if totalFound < goal {
		t.Errorf("Did not get enough content, found %d records", totalFound)
	}
	fmt.Printf("Duration: %v\n", time.Now().Sub(startTime))
}

func TestGetURL(t *testing.T) {
	c, err := testingClient()
	if err != nil {
		t.Error(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	rows := make(chan Row)
	go func() {
		err := c.GetRows(ctx, "", nil, rows)
		if err != nil {
			t.Error(err)
		}
	}()
	if err != nil {
		t.Error(err)
	}

	// Read a single row
	row := <-rows
	cancel()

	// Check if we can get the URL
	url, err := c.GetURLOfRow(row)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(url)
}
