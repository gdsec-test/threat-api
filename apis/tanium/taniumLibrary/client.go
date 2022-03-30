package taniumLibrary

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.secureserver.net/go/sso-client/sso"
	"net/http"
	"strings"
)

// APIVersion is the currently-supported version of go-tanium for the Tanium API
const APIVersion = 2

// Config contains optional fields that can be set by the caller prior to initializing a new TaniumClient
type Config struct {
	HTTPClient  *http.Client // Used for customizing HTTP requests
	baseURL     string
	username    string
	password    string
	domain      string
	Token       string
	Session     string
	Certificate *tls.Certificate
	SSOEnv      sso.Environment
}

// TaniumClient represents an authenticated session to a configured Tanium host, and is used for communication to the Tanium API.
//
// A *TaniumClient should only be used after calling NewTaniumClient(), otherwise the client will need to be manually authenticated with a call to (*TaniumClient).Login()
type TaniumClient struct {
	config *Config

	session string
	jwt     string
}

// NewTaniumClient creates a new *TaniumClient that is authenticated to the provided Tanium host using the provided credentials.
//
// The returned *TaniumClient should be used for interactions with the Tanium API, unless any errors have been returned
func NewTaniumClient(ctx context.Context, username, password, domain, host string, config *Config) (*TaniumClient, error) {
	configCopy := *config
	c := &TaniumClient{
		config: &configCopy,
	}
	if c.config.HTTPClient == nil {
		c.config.HTTPClient = http.DefaultClient
	}

	c.config.baseURL = strings.Trim(host, "/") + fmt.Sprintf("/api/v%d", APIVersion)
	c.config.username = username
	c.config.password = password
	c.config.domain = domain

	if c.config.Token != "" {
		c.session = c.config.Token
	} else if c.config.Session != "" {
		c.session = c.config.Session
		return c, nil
	}

	err := c.Login(ctx) // TODO-Tanium: Modify this later with API access

	return c, err
}

// GET performs a HTTP GET request to the specified endpoint path using the authenticated TaniumClient's session.
//
// The JSON contents of the data field for the HTTP response are returned as a []byte, allowing the caller to unmarsal the results at a later time.
// The HTTP response's status code and any encountered errors are returned as well.
func (c *TaniumClient) GET(ctx context.Context, path string) ([]byte, int, error) {
	c.ValidateSession(ctx) //TODO-Tanium: might not be needed with API access, else add it

	headers := c.getHeaders()
	return MakeRequest(ctx, "GET", c.config.baseURL+path, c.config.HTTPClient, &headers, nil)
}

// POST performs a HTTP POST request to the specified endpoint path using the authenticated TaniumClient's session and sending the specified data as the HTTP request's payload.
//
// The JSON contents of the data field for the HTTP response are returned as a []byte, allowing the caller to unmarsal the results at a later time.
// The HTTP response's status code and any encountered errors are returned as well.
func (c *TaniumClient) POST(ctx context.Context, path string, data interface{}) ([]byte, int, error) {
	c.ValidateSession(ctx) //TODO-Tanium: might not be needed with API access, else add it

	headers := c.getHeaders()
	return MakeRequest(ctx, "POST", c.config.baseURL+path, c.config.HTTPClient, &headers, data)
}
