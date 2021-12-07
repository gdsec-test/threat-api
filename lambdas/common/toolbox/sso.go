package toolbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.secureserver.net/auth-contrib/go-auth/gdsso"
	"github.secureserver.net/auth-contrib/go-auth/gdtoken"
)

const (
	ssoADURL = "api/my/ad_membership"
)

// Authorize Takes a JWT, Action, and resource and determines is the action is permitted or not
func (t *Toolbox) Authorize(ctx context.Context, jwt, action, resource string) (bool, error) {
	var span *appsectracing.Span
	span, ctx = t.TracerLogger.StartSpan(ctx, "Authorize", "auth", "jwt", "authorize")
	span.SetAppSecLogEvent()
	span.LogKV("action", action)
	span.LogKV("resource", resource)
	defer span.End(ctx)

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

	// Find the lambda resource they are referencing
	lambdas, err := t.GetModules(ctx)
	if err != nil {
		return false, fmt.Errorf("error fetching lambda list")
	}
	lambda, ok := lambdas[resource]
	if !ok {
		return false, fmt.Errorf("resource not found")
	}

	// Find the action
	span, _ = t.TracerLogger.StartSpan(ctx, "ParseAuthZStructure", "auth", "authz", "parse")
	defer span.End(ctx)
	actionObj, ok := lambda.Actions[action]
	if !ok {
		return false, fmt.Errorf("action not found")
	}

	// Check required groups, flag with any group match
	flag := 0
	for _, requiredGroup := range actionObj.RequiredADGroups {
		if _, ok := groupsMap[requiredGroup]; ok {
			flag += 1
		}
	}
	if flag == 0 {
		return false, nil
	}

	// They pass all checks for this action, they are good!
	span.LogKV("authorized", true)
	return true, nil
}

// ValidateJWT performs a simple validation of the provided JWT, returning it if it is valid
// or an error if it is now
func (t *Toolbox) ValidateJWT(ctx context.Context, jwt string) (*gdtoken.Token, error) {
	var span *appsectracing.Span
	span, ctx = t.TracerLogger.StartSpan(ctx, "ValidateJWT", "auth", "jwt", "validate")
	span.LogKV("JWTLength", len(jwt))
	defer span.End(ctx)

	// Check formatting and build token
	token, err := gdtoken.FromStringV2(jwt)
	if err != nil {
		span.AddError(err)
		return nil, err
	}

	validator := gdsso.ValidatorFactory(t.SSOHostURL)
	if validator == nil {
		err = fmt.Errorf("failed to get validator factory")
		span.AddError(err)
		return nil, err
	}

	err = validator.Validate(ctx, jwt)
	if err != nil {
		span.AddError(err)
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
	var span *appsectracing.Span
	span, ctx = t.TracerLogger.StartSpan(ctx, "GetJWTADGroups", "auth", "jwt", "getadgroups")
	defer span.End(ctx)

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
func GetJWTFromRequest(request events.APIGatewayProxyRequest) string {
	// Try the auth header
	authHeader, ok := request.Headers["Authorization"]
	if !ok { // due to bug with APIGatewayProxyRequest being case-sensitive
		authHeader, ok = request.Headers["authorization"]
	}
	if ok && strings.HasPrefix(strings.ToLower(authHeader), "sso-jwt ") {
		return authHeader[8:]
	}

	// Try cookies
	cookieHeader, ok := request.Headers["cookie"]
	if !ok {
		cookieHeader, ok = request.Headers["Cookie"]
	}
	if ok {
		cookies := parseQueryParams(cookieHeader)
		if jwt, ok := cookies["auth_jomax"]; ok {
			return strings.Trim(jwt, " ")
		}
	}
	return ""
}

// GetOriginalRequester pulls out the forwarded requester name if it is present as `for` attribute
// see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Forwarded
func GetOriginalRequester(request events.APIGatewayProxyRequest) string {
	// Try cookies
	forwardedHeader, ok := request.Headers["Forwarded"]
	if !ok { // due to bug with APIGatewayProxyRequest being case-sensitive
		forwardedHeader, ok = request.Headers["forwarded"]
	}
	if ok {
		forwardedParams := parseQueryParams(forwardedHeader)
		if originRequester, ok := forwardedParams["for"]; ok {
			return strings.Trim(originRequester, " ")
		}
	}
	return ""
}

func parseQueryParams(cookies string) map[string]string {
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
