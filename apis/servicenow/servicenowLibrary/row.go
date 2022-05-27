package servicenowLibrary

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
)

const (
	// Limit of results to get per snow page, default snow is 10000
	limitPerPage = 1000
	// Limit of concurrent threads making requests
	maxThreads = 10
)

type RowsResponse struct {
	Result []map[string]interface{} `json:"result"`
}

// Row is a row in a snow table
type Row map[string]interface{}

// GetURLOfRow Gets a direct link to this particular ticket/row
func (c *Client) GetURLOfRow(r Row) (string, error) {
	sysID, ok := r["sys_id"]
	if !ok {
		return "", fmt.Errorf("failed to find ticket sys_id")
	}
	return fmt.Sprintf("%s/%s.do?sys_id=%s", c.URL, c.tableName, sysID), nil
}

// GetRows gets the rows in the service now table and sends them to the passed in rows channel.
// It will close the channel when it finishes or errors. It will return an error if some page fails to return results.
//
// additionalURLValues are additional parameters to send in the GET request for each page.  See this: https://developer.servicenow.com/dev.do#!/reference/api/orlando/rest/c_TableAPI.
// The query is an optional SNOW encoded query. To find a SNOW encoded query, right click the desired query/filter in SNOW and press "copy Query".
func (c *Client) GetRows(ctx context.Context, query string, additionalURLValues url.Values, rows chan Row) error {
	// This function spawns multiple threads limited by maxThreads.
	// Each thread will fetch a SNOW page and send any results to the returned channel.
	// Since we don't know the total number of pages, once a single thread finds gets a 404
	// it singles to the spawner thread to stop creating threads, wait on all the others to finish, then be done.

	// Setup
	page := 0
	// Channel to limit our thread count
	threadLimit := make(chan int, maxThreads)
	// Channel to mark when we don't need to keep looking at the next pages
	noMorePages := make(chan error, 1)
	wg := sync.WaitGroup{}
	defer close(rows)
	defer close(threadLimit)
	defer close(noMorePages)

	// markDone is used to tell the spawner to stop spawning threads, and if we had an error
	markDone := func(threadErr error) {
		select {
		// Set the err to this thread's error
		case noMorePages <- threadErr:
		default:
		}
	}

	// Keep making threads to crawl pages until we find one request that returns a non 200 code
	for {
		// Start new thread to make a request, and send results
		select {
		case threadLimit <- 1: // Wait for thread to be available
		case err := <-noMorePages: // Check if we no longer need to spawn pages
			// wait for current threads to finish
			wg.Wait()
			return err
		case <-ctx.Done(): // Context cancelled
			wg.Wait()
			return ctx.Err()
		}

		// Spawn thread
		wg.Add(1)
		go func(page int) {
			defer func() { <-threadLimit }() // Mark a thread available
			defer wg.Done()

			// Build URL
			params := url.Values{}
			params.Add("sysparm_limit", fmt.Sprintf("%d", limitPerPage))
			params.Add("sysparm_offset", fmt.Sprintf("%d", page*limitPerPage))
			if query != "" {
				params.Add("sysparm_query", fmt.Sprintf("%s", query))
			}
			// Add additional values
			for key, values := range additionalURLValues {
				for _, value := range values {
					params.Add(key, value)
				}
			}
			url := fmt.Sprintf("%s?%s", c.tableURL, params.Encode())

			// Make request
			resp, err := c.HttpRequest(ctx, http.MethodGet, url, nil, "")
			if err != nil {
				markDone(err)
				return
			}

			// Check if we are done
			switch resp.StatusCode {
			case 200:
			case 404:
				// Done reading pages
				markDone(nil)
				return
			default:
				// Bad status code
				markDone(fmt.Errorf("bad status code: %d", resp.StatusCode))
				return
			}

			// Parse
			results := RowsResponse{}
			decoder := json.NewDecoder(resp.Body)
			err = decoder.Decode(&results)
			resp.Body.Close()
			if err != nil {
				markDone(err)
				return
			}

			// Send results
			for _, entry := range results.Result {
				select {
				case rows <- Row(entry):
				case <-ctx.Done():
					markDone(ctx.Err())
					return
				}
			}
		}(page)

		page++
	}
}

// GetUnique is a simpler version of GetRows, works on cases where a single unique row is returned for a sysID as opposed to entire table rows returned in GetRows()
func (c *Client) GetUniqueRow(ctx context.Context, sysID string, query string, additionalURLValues url.Values) (Row, error) {
	//BuildURL
	params := url.Values{}
	params.Add("sysparm_limit", fmt.Sprintf("%d", limitPerPage))
	if query != "" {
		params.Add("sysparm_query", fmt.Sprintf("%s", query))
	}
	//Add additionalvalues
	for key, values := range additionalURLValues {
		for _, value := range values {
			params.Add(key, value)
		}
	}

	url := fmt.Sprintf("%s/%s?%s", c.tableURL, sysID, params.Encode())

	//Make request
	resp, err := c.HttpRequest(ctx, http.MethodGet, url, nil, "")
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("status not found")
	default:
		//Bad status code
		return nil, fmt.Errorf("bad status code:%d", resp.StatusCode)

	}

	//Parse
	row := Row{}
	err = json.NewDecoder(resp.Body).Decode(&row)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	return row, nil
}
