package toolbox

import (
	"net/http"

	"go.elastic.co/apm/module/apmhttp"
)

// This file contains useful tools and object for tracing and logging

// GetHTTPClient wraps the provided http client into a new one that send stats to our tracing server.
// If nil is provided, then http.DefaultClient will be wrapped.
func (t *Toolbox) GetHTTPClient(inputClient *http.Client) *http.Client {
	return apmhttp.WrapClient(inputClient)
}
