package servicenowLibrary

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
)

// ServiceNow URLs
const (
	// URL for a table. %s, %s -> Snow base URL, Tablename
	tableURL = "%s/api/now/v1/table/%s"
	// URL for uploading a file %s -> Snow base URL
	fileUploadURL = "%s/api/now/v1/attachment/file"
)

// Config to create a service now client from
type Config struct {
	URL      string
	Username string
	Password string
}

// Client is a service now client for a specific servicenow table
type Client struct {
	Config

	tableName     string
	tableURL      string
	fileUploadURL string
}

// NewFromConfig Returns a client for the config that is passed
func NewFromConfig(config *Config, tableName string) (*Client, error) {
	if tableName == "" {
		return nil, errors.New("table name is invalid")
	} else if config.URL == "" {
		return nil, errors.New("instance url is invalid")
	}

	// Make sure the URL does not end in a slash
	if config.URL[len(config.URL)-1] == '/' {
		config.URL = config.URL[0 : len(config.URL)-1]
	}

	// Validate URLs
	tableURL, err := url.Parse(fmt.Sprintf(tableURL, config.URL, tableName))
	if err != nil {
		return nil, err
	}

	fileUploadURL, err := url.Parse(config.URL + "/api/now/v1/attachment/file")
	if err != nil {
		return nil, err
	}

	c := &Client{
		Config:        *config,
		tableName:     tableName,
		tableURL:      tableURL.String(),
		fileUploadURL: fileUploadURL.String(),
	}

	return c, nil
}

// New Returns a new client from raw credential details
func New(snowURL string, username string, password string, tableName string) (*Client, error) {
	config := &Config{
		URL:      snowURL,
		Username: username,
		Password: password,
	}

	return NewFromConfig(config, tableName)
}

// Utility function to upload files
func (c *Client) UploadFile(ctx context.Context, fileName string, byteFileData []byte, sysID string) error {
	paramValues := url.Values{
		"file_name":    []string{fileName},
		"table_name":   []string{c.tableName},
		"table_sys_id": []string{sysID},
	}

	uploadURL := fmt.Sprintf("%s?%s", c.fileUploadURL, paramValues.Encode())

	_, err := c.HttpRequest(ctx, http.MethodPost, uploadURL, bytes.NewReader(byteFileData), "application/octet-stream")
	if err != nil {
		return err
	}

	return err
}

func (c *Client) HttpRequestAndRead(ctx context.Context, method, url string, body io.Reader, contentType string) ([]byte, error) {
	resp, err := c.HttpRequest(ctx, method, url, body, contentType)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (c *Client) HttpRequest(ctx context.Context, method, url string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	if method == http.MethodPost || method == http.MethodPut {
		req.Header.Set("Content-Type", contentType)
	}
	req.SetBasicAuth(c.Username, c.Password)

	return http.DefaultClient.Do(req)
}
