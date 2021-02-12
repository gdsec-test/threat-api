package toolbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/opentracing/opentracing-go"
	"github.secureserver.net/auth-contrib/go-auth/gdsso"
	"github.secureserver.net/auth-contrib/go-auth/gdtoken"
)

const (
	ssoADURL = "api/my/ad_membership"
)

// PermissionsModel is the structure that defines
type PermissionsModel struct {
	Resources map[string]struct {
		// Actions that can be performed in this module
		Actions map[string]struct {
			// Required AD groups to perform this action
			RequiredGroups []string
		}
	}
}

// Authorize Takes a JWT, Action, and resource and determines is the action is permitted or not
func (t *Toolbox) Authorize(ctx context.Context, jwt, action, resource string) (bool, error) {
	var span opentracing.Span
	span, ctx = opentracing.StartSpanFromContext(ctx, "Authorize")
	span.LogKV("action", action, "resource", resource)
	defer span.Finish()

	// Validate JWT
	_, err := t.ValidateJWT(ctx, jwt)
	if err != nil {
		return false, err
	}

	// Get the user groups
	groups, err := t.GetJWTGroups(ctx, jwt)
	if err != nil {
		return false, fmt.Errorf("error getting user groups: %w", err)
	}
	// Convert to map
	groupsMap := map[string]struct{}{}
	for _, group := range groups {
		groupsMap[group] = struct{}{}
	}

	// Go through the permission structure and make sure all requirements are satisfied
	span, _ = opentracing.StartSpanFromContext(ctx, "Parse")
	defer span.Finish()
	r, ok := t.permissionsModel.Resources[resource]
	if !ok {
		return false, fmt.Errorf("resource not found")
	}
	// Find the action
	a, ok := r.Actions[action]
	if !ok {
		return false, fmt.Errorf("action not found")
	}
	// Check required groups
	for _, requiredGroup := range a.RequiredGroups {
		if _, ok := groupsMap[requiredGroup]; !ok {
			return false, fmt.Errorf("not in required group %s", requiredGroup)
		}
	}

	// They pass all checks for this action, they are good!
	return true, nil
}

// ValidateJWT performs a simple validation of the provided JWT, returning it if it is valid
// or an error if it is now
func (t *Toolbox) ValidateJWT(ctx context.Context, jwt string) (*gdtoken.Token, error) {
	var span opentracing.Span
	span, ctx = opentracing.StartSpanFromContext(ctx, "ValidateJWT")
	defer span.Finish()

	// Check formatting and build token
	token, err := gdtoken.FromStringV2(jwt)
	if err != nil {
		return nil, err
	}

	validator := gdsso.ValidatorFactory(t.SSOHostURL)
	if validator == nil {
		return nil, fmt.Errorf("failed to get validator factory")
	}

	err = validator.Validate(ctx, jwt)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// GetJWTGroups Gets the groups in the provided JWT.  It will make a request to the SSO server
func (t *Toolbox) GetJWTGroups(ctx context.Context, jwt string) ([]string, error) {
	return t.getJWTADGroups(ctx, jwt)
}

// getJWTADGroups makes a request to SSO to get the AD groups of the JWT.
// Hopefully this can be moved to the godaddy SSO library someday
// https://github.secureserver.net/auth-contrib/go-auth/issues/30
func (t *Toolbox) getJWTADGroups(ctx context.Context, jwt string) ([]string, error) {
	var span opentracing.Span
	span, ctx = opentracing.StartSpanFromContext(ctx, "GetJWTADGroups")
	defer span.Finish()

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/%s", strings.Trim(t.SSOHostURL, "/"), ssoADURL), nil)
	if err != nil {
		return nil, err
	}

	// Add headers
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "sso-jwt "+jwt)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}

	groupsResponse := struct {
		Code    int64  `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Groups []string `json:"groups"`
		} `json:"data"`
	}{}

	err = json.NewDecoder(resp.Body).Decode(&groupsResponse)
	if err != nil {
		return nil, err
	}

	return groupsResponse.Data.Groups, nil
}

// GetJWTFromRequest pulls out the JWT from the request.
// It first checks the Authorization header, then looks for the auth_jomax cookie
func (t *Toolbox) GetJWTFromRequest(request events.APIGatewayProxyRequest) string {
	// Try the auth header
	authHeader, ok := request.Headers["Authorization"]
	if ok && strings.HasPrefix(strings.ToLower(authHeader), "sso-jwt ") {
		return authHeader[8:]
	}

	// Try cookies
	cookieHeader, ok := request.Headers["cookie"]
	if ok {
		cookies := parseCookies(cookieHeader)
		if jwt, ok := cookies["auth_jomax"]; ok {
			return jwt
		}
	}
	return ""
}

func parseCookies(cookies string) map[string]string {
	ret := map[string]string{}

	cookiesList := strings.Split(cookies, ";")
	for _, cookie := range cookiesList {
		cookieEqual := strings.Index(cookie, "=")
		if cookieEqual == -1 {
			continue
		}
		ret[strings.Trim(cookie[0:cookieEqual], " ")] = strings.Trim(cookie[cookieEqual+1:], " ")
	}

	return ret
}
