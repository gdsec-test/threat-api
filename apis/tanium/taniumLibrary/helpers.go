package taniumLibrary

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type genericResponse struct {
	Data *json.RawMessage `json:"data"`
	Text string           `json:"text"`
}

// NoStatus indicates that an error occurred before a valid HTTP response status code was received
const NoStatus int = -1

// MakeRequest is a helper function for making Tanium API requests, parsing the response data, and returning the result, HTTP status, and any errors to the caller
func MakeRequest(ctx context.Context, method string, url string, client *http.Client, headers *map[string]string, payload interface{}) ([]byte, int, error) {
	var req *http.Request
	var err error

	if payload == nil {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	} else {
		// the provided payload is assumed to be JSON, since Tanium only accepts JSON-formatted data
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, NoStatus, err
		}

		req, err = http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(data))
	}

	if err != nil {
		return nil, NoStatus, err
	}

	if headers != nil {
		for k, v := range *headers {
			req.Header.Set(k, v)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, NoStatus, err
	}

	defer resp.Body.Close()

	// Handle cases when HTTP errors are returned or no JSON content is returned
	if strings.ToLower(resp.Header.Get("Content-Type")) != "application/json" {
		rawdata, err := ioutil.ReadAll(resp.Body)
		return rawdata, resp.StatusCode, err
	}

	data := genericResponse{}

	d := json.NewDecoder(resp.Body)
	d.DisallowUnknownFields()
	err = d.Decode(&data)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	if data.Text != "" {
		// An error was returned
		return nil, resp.StatusCode, fmt.Errorf(data.Text)
	}

	rawdata, err := data.Data.MarshalJSON()
	if err != nil {
		return nil, resp.StatusCode, err
	}

	return rawdata, resp.StatusCode, nil
}
