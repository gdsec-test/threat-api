package main

import "encoding/json"

// Response is the standardized response object sent to the user
type Response struct {
	JobID string      `json:"job_id"` // Job id created or fetching status of
	Data  interface{} `json:"dat"`    // Raw data from the DB
	Error string      `json:"error"`  // Any error
}

// Marshal to a json string
func (r *Response) Marshal() string {
	ret, err := json.Marshal(r)
	if err != nil {
		return `{"error":"server error marshalling response"}`
	}

	return string(ret)
}

// ErrorResponse is a helper to build a response with an error
func ErrorResponse(err string) *Response {
	return &Response{Error: err}
}
