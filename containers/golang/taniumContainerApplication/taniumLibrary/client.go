package taniumLibrary

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// APIVersion is the currently-supported version of go-tanium for the Tanium API
const (
	APIVersion = 2
)

// Config contains optional fields that can be set by the caller prior to initializing a new TaniumClient
type Config struct {
	HTTPClient *http.Client // Used for customizing HTTP requests
	baseURL    string
	APIKey     string
}

// TaniumClient represents an authenticated session to a configured Tanium host, and is used for communication to the Tanium API.
type TaniumClient struct {
	config *Config
}

// NewTaniumClient creates a new *TaniumClient that is authenticated to the provided Tanium host using the provided credentials.
//
// The returned *TaniumClient should be used for interactions with the Tanium API, unless any errors have been returned
func NewTaniumClient(ctx context.Context, host string) *TaniumClient {
	var configCopy Config
	c := &TaniumClient{
		config: &configCopy,
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if c.config.HTTPClient == nil {
		client := &http.Client{Transport: tr}
		c.config.HTTPClient = client
	}

	c.config.baseURL = strings.Trim(host, "/") + fmt.Sprintf("/api/v%d", APIVersion)

	c.config.APIKey = os.Getenv("TANIUM_API_KEY")

	return c
}

// GET performs HTTP GET request to the specified endpoint path using the authenticated TaniumClient's session.
//
// The JSON contents of the data field for the HTTP response are returned as a []byte, allowing the caller to unmarsal the results at a later time.
// The HTTP response's status code and any encountered errors are returned as well.
func (c *TaniumClient) GET(ctx context.Context, path string) ([]byte, int, error) {

	headers := c.getHeaders()
	return MakeRequest(ctx, "GET", c.config.baseURL+path, c.config.HTTPClient, &headers, nil)
}

// POST performs a HTTP POST request to the specified endpoint path using the authenticated TaniumClient's session and sending the specified data as the HTTP request's payload.
//
// The JSON contents of the data field for the HTTP response are returned as a []byte, allowing the caller to unmarsal the results at a later time.
// The HTTP response's status code and any encountered errors are returned as well.
func (c *TaniumClient) POST(ctx context.Context, path string, data interface{}) ([]byte, int, error) {

	headers := c.getHeaders()
	return MakeRequest(ctx, "POST", c.config.baseURL+path, c.config.HTTPClient, &headers, data)
}
