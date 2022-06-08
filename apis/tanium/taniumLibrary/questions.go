package taniumLibrary

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	pollRate = 5
)

// CanParse returns whether or not the input Tanium question can be created as an ask-able question with the Tanium server's sensors and packages.
func (c *TaniumClient) CanParse(ctx context.Context, question string) (bool, error) {

	payload := struct {
		Text string `json:"text"`
	}{
		Text: question,
	}

	recvdata, status, err := c.POST(ctx, "/parse_question", &payload)
	if err != nil {
		return false, err
	}

	// one or many results, first is closest - same as you submitted best practice. When it differs - check on logs and questions

	if status != 200 {
		return false, fmt.Errorf("received non-200 status code: %d", status)
	}

	questions := make([]QuestionDefinition, 0)

	err = json.Unmarshal(recvdata, &questions)
	if err != nil {
		return false, err
	}

	return len(questions) > 0, nil
}

// CreateQuestion creates and asks a Tanium question using the provided question text, returning any errors received.
//
// Only the Id field of the returned *Question will contain reliable information about the created question. To retrieve more information about the asked Tanium question, call (*Question).GetDefinition() first.
func (c *TaniumClient) CreateQuestion(ctx context.Context, question string) (*Question, error) {
	q := struct {
		QueryText string `json:"query_text"`
	}{
		QueryText: question,
	}

	recvdata, status, err := c.POST(ctx, "/questions", &q)
	if err != nil {
		return nil, err
	} else if status != 200 {
		return nil, fmt.Errorf("received non-200 status code: %d", status)
	}

	data := Question{
		client: c,
	}

	err = json.Unmarshal(recvdata, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

// GetDefinition populates the provided Question with detailed information about its creation/supported sensors/etc. from Tanium based on the question's Id, returning any errors received.
func (q *Question) GetDefinition(ctx context.Context) error {

	recvdata, status, err := q.client.GET(ctx, fmt.Sprintf("/questions/%d", q.Id))
	if err != nil {
		return err
	} else if status != 200 {
		return fmt.Errorf("received non-200 status code: %d", status)
	}

	err = json.Unmarshal(recvdata, q)
	if err != nil {
		return err
	}

	return nil
}

// GetResultInfo retrieves information about the current status of the results for the provided Question, returning any errors received.
//
// This information *does not* contain any rows of data, but is useful for determining when the asked question has received all available responses.
// To retrieve responses to the Question, call GetResults.
func (q *Question) GetResultInfo(ctx context.Context) ([]ResultSet, error) {

	recvdata, status, err := q.client.GET(ctx, fmt.Sprintf("/result_info/question/%d", q.Id))
	if err != nil {
		return nil, err
	} else if status != 200 {
		return nil, fmt.Errorf("received non-200 status code: %d", status)
	}

	data := struct {
		ResultInfos []ResultSet `json:"result_infos"`
	}{}

	err = json.Unmarshal(recvdata, &data)
	if err != nil {
		return nil, err
	}

	return data.ResultInfos, nil
}

// isCompleted determines if the asked Question has completed, based off of information from the Tanium API docs or if appproximately 90% of all machines have been tested
func (r ResultSet) isCompleted() bool {
	return r.EstimatedTotal == r.MRTested || r.MRTested >= int(0.9*float64(r.EstimatedTotal))
}

// WaitForResults will continue to check the current state of the provided Question, checking every 5 seconds if the Question has completed/received at least n results, and will only return if an error has been encountered, the context has been cancelled, or the Question has completed being asked.
//
// If n is less than 0, then all results will be waited for, otherwise this function will wait until at least n number of results (within the total number estimated) have been received
func (q *Question) WaitForResults(ctx context.Context, n int) error {
	var resultFunc func(ri ResultSet) bool
	if n < 0 {
		resultFunc = func(ri ResultSet) bool {
			return ri.isCompleted()
		}
	} else {
		resultFunc = func(ri ResultSet) bool {
			adjusted := ri.EstimatedTotal + 1
			if n < adjusted {
				adjusted = n
			}
			return ri.isCompleted() || ri.Tested >= adjusted
		}
	}

	for {
		resultInfo, err := q.GetResultInfo(ctx)
		if err != nil {
			return err
		}
		if len(resultInfo) < 1 {
			return nil
		}
		if resultFunc(resultInfo[0]) {
			return nil
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second * pollRate):
			continue
		}
	}
}

// GetColumns retrieves an array of all column objects for the asked question.
//
// This function will wait for one result to let the question columns populate
func (q *Question) GetColumns(ctx context.Context) ([]Column, error) {
	q.WaitForResults(ctx, 1) // wait for at least one result to come in

	offset, count := 0, 1

	recvdata, status, err := q.client.GET(ctx, fmt.Sprintf("/result_data/question/%d?row_start=%d&row_count=%d", q.Id, offset, count))
	if err != nil || status != 200 {
		return nil, err
	}

	data := struct {
		MaxAvailableAge string      `json:"max_available_age"`
		Now             string      `json:"now"`
		ResultSets      []ResultSet `json:"result_sets"`
	}{}

	err = json.Unmarshal(recvdata, &data)
	if err != nil {
		return nil, err
	}

	// only a single ResultSet exists for a single question
	resultSet := data.ResultSets[0]

	return resultSet.Columns, nil
}

// GetQuestionResults Retrieves the currently-available results to an asked question.
//
// If the question is currently in progress, available results will be returned through the channel. The channel will not be closed until the search is finished and all results are sent.
//
// If the results in the question may change during the question's progress, call WaitForResults before retrieving the results.
func (q *Question) GetResults(ctx context.Context) (chan Row, error) {
	count := 100
	bufferSize := 4

	results := make(chan Row, count*bufferSize)

	go func() {
		defer close(results)

		recvdata, status, err := q.client.GET(ctx, fmt.Sprintf("/result_data/question/%d?include_hashes_flag=1", q.Id))
		if err != nil || status != 200 {
			// either an error occurred while getting the API endpoint or unmarshalling the received data or we were not able to get results for the given offset/row count
			return
		}

		data := struct {
			MaxAvailableAge string      `json:"max_available_age"`
			Now             string      `json:"now"`
			ResultSets      []ResultSet `json:"result_sets"`
		}{}

		err = json.Unmarshal(recvdata, &data)
		if err != nil {
			return
		}

		// only a single ResultSet exists for a single question
		resultSet := data.ResultSets[0]

		for _, r := range resultSet.Rows {
			select {
			case results <- r:
			case <-ctx.Done():
				return
			}
		}
	}()

	return results, nil
}

// String returns the string representation of all pieces of data within the provided Cell, joining multiple with the ", " separator
func (c Cell) String() string {
	s := make([]string, 0)
	for _, e := range c {
		s = append(s, e.Text)
	}
	return strings.Join(s, ", ")
}

// String returns the string representation of all Cell structures within the provided Row, joining multiple Cell strings with the ", " separator
func (r Row) String() string {
	s := make([]string, 0)
	for _, d := range r.Data {
		s = append(s, d.String())
	}

	return strings.Join(s, ", ")
}
