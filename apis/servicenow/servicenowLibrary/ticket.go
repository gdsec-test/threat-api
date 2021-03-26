package servicenowLibrary

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

type Body struct {
	Impact           string `json:"u_impact,omitempty"`
	Urgency          string `json:"u_urgency,omitempty"`
	State            string `json:"u_state,omitempty"`
	AssignmentGroup  string `json:"u_assignment_group,omitempty"`
	IncidentCategory string `json:"u_category,omitempty"`
	SubCategory      string `json:"u_sub_category,omitempty"`
	DetectionMethod  string `json:"u_detection_method,omitempty"`
	Title            string `json:"u_title"`
	Summary          string `json:"u_summary"`
	EventTime        string `json:"u_event_time,omitempty"`
	DetectTime       string `json:"u_detect_time,omitempty"`
	Worklog          string `json:"u_narrative,omitempty"`
}

type Ticket struct {
	Number   string
	SysID    string
	Warnings []error
}

func (t *Ticket) HasWarnings() bool {
	return len(t.Warnings) > 0
}

//Creates a new ticket and returns a Ticket structure - ticket number, sys_id, warnings (file upload failures)
func (c *Client) CreateTicket(ctx context.Context, body *Body, fileMap map[string][]byte, failOnWarning bool) (*Ticket, error) {
	jsonBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	data, err := c.httpRequestAndRead(ctx, http.MethodPost, c.tableURL, bytes.NewBuffer(jsonBytes), "application/json")
	if err != nil {
		return nil, err
	}

	result := struct {
		Response struct {
			SysID        string `json:"sys_id"`
			TicketNumber string `json:"u_number"`
		} `json:"result"`
	}{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, err
	}

	var ticket = new(Ticket)
	for fileName, byteFileData := range fileMap {
		err = c.uploadFile(ctx, fileName, byteFileData, result.Response.SysID)
		if err != nil {
			if failOnWarning {
				return nil, err
			}
			ticket.Warnings = append(ticket.Warnings, err)
		}
	}

	ticket.Number = result.Response.TicketNumber
	ticket.SysID = result.Response.SysID

	return ticket, nil
}

// Utility function to return the sys_id of the ticket number that is passed
func (c *Client) getSysIdFromTicketNumber(ctx context.Context, ticketNumber string) (string, error) {
	paramValues := url.Values{
		"u_number": []string{ticketNumber},
	}

	getTicketURL := fmt.Sprintf("%s?%s", c.tableURL, paramValues.Encode())

	data, err := c.httpRequestAndRead(ctx, http.MethodGet, getTicketURL, nil, "")
	if err != nil {
		return "", err
	}

	var result map[string][]map[string]interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		return "", err
	}

	tickets, ok := result["result"]
	if !ok {
		return "", errors.New("result not found in get response")
	} else if len(tickets) == 0 {
		return "", errors.New("no tickets returned for the ticket number")
	}

	sysID, ok := tickets[0]["sys_id"]
	if !ok {
		return "", errors.New("sys_id not found in the ticket returned")
	}

	sysIDStr, ok := sysID.(string)
	if !ok {
		return "", errors.New("error in interface to string conversion")
	}

	return sysIDStr, nil
}

// AppendToSnowTicketWorklog Append using Ticket number
func (c *Client) AppendToSnowTicketWorklog(ctx context.Context, ticketNumber string, worklogText string) error {
	sysid, err := c.getSysIdFromTicketNumber(ctx, ticketNumber)
	if err != nil {
		return err
	}

	return c.AppendToSnowTicketWorklogWithSysId(ctx, sysid, worklogText)
}

// AppendToSnowTicketWorklogWithSysId Append using sys_id
func (c *Client) AppendToSnowTicketWorklogWithSysId(ctx context.Context, sysid string, worklogText string) error {
	var err error
	jsonBytes, err := json.Marshal(map[string]string{"u_narrative": worklogText})
	if err != nil {
		return err
	}

	editTicketURLString, err := url.Parse(c.tableURL + "/" + url.QueryEscape(sysid))
	if err != nil {
		return err
	}

	paramValues := url.Values{
		"sysparm_exclude_ref_link": []string{"true"},
	}

	editTicketURL := fmt.Sprintf("%s?%s", editTicketURLString.String(), paramValues.Encode())

	_, err = c.httpRequest(ctx, http.MethodPut, editTicketURL, bytes.NewReader(jsonBytes), "application/json")
	if err != nil {
		return err
	}

	return nil
}

// CloseSnowTicket Close ticket using Ticket Number
func (c *Client) CloseSnowTicket(ctx context.Context, ticketNumber string) error {
	sysid, err := c.getSysIdFromTicketNumber(ctx, ticketNumber)
	if err != nil {
		return err
	}

	return c.CloseSnowTicketWithSysId(ctx, sysid)
}

// CloseSnowTicketWithSysId Close Ticket using sys_id
func (c *Client) CloseSnowTicketWithSysId(ctx context.Context, sysid string) error {
	var err error
	jsonBytes, err := json.Marshal(map[string]string{"u_state": "Closed"})
	if err != nil {
		return err
	}

	editTicketURLString, err := url.Parse(c.tableURL + "/" + url.QueryEscape(sysid))
	if err != nil {
		return err
	}

	paramValues := url.Values{
		"sysparm_exclude_ref_link": []string{"true"},
	}

	editTicketURL := fmt.Sprintf("%s?%s", editTicketURLString.String(), paramValues.Encode())

	_, err = c.httpRequest(ctx, http.MethodPut, editTicketURL, bytes.NewReader(jsonBytes), "application/json")
	if err != nil {
		return err
	}

	return nil
}
