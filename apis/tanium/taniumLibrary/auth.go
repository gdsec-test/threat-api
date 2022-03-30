package taniumLibrary

import "context"

func (c *TaniumClient) getHeaders() map[string]string {
	headers := make(map[string]string, 0)
	headers["session"] = c.session
	return headers
}

// TODO-tanium: might not need it with API access
func (c *TaniumClient) ValidateSession(ctx context.Context) (bool, error) {
	return true, nil
}

func (c *TaniumClient) Login(ctx context.Context) error {
	return nil
}
