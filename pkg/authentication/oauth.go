package authentication

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// oauth.go logs a session in against an OAuth2 token endpoint instead of a
// login form:
//
//	login:
//	  type: oauth2_client_credentials   # or oauth2_refresh_token
//	  token_url: https://idp.example.com/oauth/token
//	  client_id: scanner
//	  client_secret: "{{env:SCANNER_CLIENT_SECRET}}"
//	  scope: "read write"
//	  audience: https://api.example.com   # client_credentials only
//	  refresh_token: "{{env:REFRESH}}"    # oauth2_refresh_token only
//	  auth_style: header                  # or body; empty tries header, then body
//
// The access token becomes `Authorization: <token_type> <access_token>`, and
// the response's expires_in is kept (Session.ExpiresAt) so a scan's
// LiveSession refreshes the token shortly before it expires instead of
// waiting for the first 401. A rotated refresh_token replaces the configured
// one for the next refresh.

// executeOAuth2Login runs sess's OAuth2 grant and sets its Authorization
// header and expiry.
func executeOAuth2Login(ctx context.Context, sess *Session, client *http.Client, tr *loginTrace) error {
	lf := sess.Login
	f, err := resolveOAuth2Fields(lf)
	if err != nil {
		return loginFailf(LoginReasonInvalidFlow, "session %q: %w", sess.Name, err)
	}
	tr.begin(-1, f.tokenURL)

	c := withLoginJar(client, nil)
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	c.Transport = &oauth2Transport{base: base, headers: f.headers, tr: tr}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c)

	style := oauth2.AuthStyleAutoDetect
	switch strings.ToLower(strings.TrimSpace(lf.AuthStyle)) {
	case OAuth2AuthStyleHeader:
		style = oauth2.AuthStyleInHeader
	case OAuth2AuthStyleBody:
		style = oauth2.AuthStyleInParams
	}

	var tok *oauth2.Token
	switch lf.Type {
	case LoginTypeOAuth2ClientCredentials:
		cc := clientcredentials.Config{
			ClientID:     f.clientID,
			ClientSecret: f.clientSecret,
			TokenURL:     f.tokenURL,
			Scopes:       f.scopes,
			AuthStyle:    style,
		}
		if f.audience != "" {
			cc.EndpointParams = url.Values{"audience": {f.audience}}
		}
		tok, err = cc.Token(ctx)
	case LoginTypeOAuth2RefreshToken:
		oc := oauth2.Config{
			ClientID:     f.clientID,
			ClientSecret: f.clientSecret,
			Endpoint:     oauth2.Endpoint{TokenURL: f.tokenURL, AuthStyle: style},
			Scopes:       f.scopes,
		}
		tok, err = oc.TokenSource(ctx, &oauth2.Token{RefreshToken: f.refreshToken}).Token()
	default:
		return loginFailf(LoginReasonInvalidFlow, "session %q: login type %q is not an OAuth2 type", sess.Name, lf.Type)
	}
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) {
			msg := re.ErrorCode
			if re.ErrorDescription != "" {
				msg += ": " + re.ErrorDescription
			}
			if msg == "" && re.Response != nil {
				msg = re.Response.Status
			}
			return loginFailf(LoginReasonUnexpectedStatus, "session %q: oauth2 token request to %s failed: %s", sess.Name, f.tokenURL, msg)
		}
		return loginFailf(LoginReasonNetworkError, "session %q: oauth2 token request to %s failed: %w", sess.Name, f.tokenURL, err)
	}
	if tok.AccessToken == "" {
		return loginFailf(LoginReasonExtractFailed, "session %q: oauth2 token response from %s has no access_token", sess.Name, f.tokenURL)
	}

	if sess.Headers == nil {
		sess.Headers = make(map[string]string)
	}
	sess.Headers["Authorization"] = tok.Type() + " " + tok.AccessToken
	sess.expiresAt = tok.Expiry
	if lf.Type == LoginTypeOAuth2RefreshToken && tok.RefreshToken != "" && tok.RefreshToken != f.refreshToken {
		// Rotated: the old refresh token is spent.
		lf.RefreshToken = tok.RefreshToken
	}
	sess.hydrated = true
	return nil
}

// oauth2Fields are a flow's OAuth2 values with templates expanded.
type oauth2Fields struct {
	tokenURL, clientID, clientSecret, audience, refreshToken string
	scopes                                                   []string
	headers                                                  map[string]string
}

func resolveOAuth2Fields(lf *LoginFlow) (*oauth2Fields, error) {
	f := &oauth2Fields{}
	for _, v := range []struct {
		name string
		in   string
		out  *string
	}{
		{"token_url", lf.TokenURL, &f.tokenURL},
		{"client_id", lf.ClientID, &f.clientID},
		{"client_secret", lf.ClientSecret, &f.clientSecret},
		{"audience", lf.Audience, &f.audience},
		{"refresh_token", lf.RefreshToken, &f.refreshToken},
	} {
		s, err := substituteVars(v.in, nil)
		if err != nil {
			return nil, fmt.Errorf("login.%s: %w", v.name, err)
		}
		*v.out = strings.TrimSpace(s)
	}
	scope, err := substituteVars(lf.Scope, nil)
	if err != nil {
		return nil, fmt.Errorf("login.scope: %w", err)
	}
	f.scopes = splitScopes(scope)
	if f.headers, err = substituteHeaders(lf.Headers, nil); err != nil {
		return nil, fmt.Errorf("login.headers: %w", err)
	}
	if f.tokenURL == "" {
		return nil, errors.New("login.token_url is empty")
	}
	if lf.Type == LoginTypeOAuth2RefreshToken && f.refreshToken == "" {
		return nil, errors.New("login.refresh_token is empty")
	}
	return f, nil
}

// splitScopes splits a space- or comma-separated scope list.
func splitScopes(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' || r == '\n' })
}

// oauth2Transport adds the flow's login.headers to the token request and
// records what came back for CheckLogin.
type oauth2Transport struct {
	base    http.RoundTripper
	headers map[string]string
	tr      *loginTrace
}

func (t *oauth2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(t.headers) > 0 {
		req = req.Clone(req.Context())
		applyRequestHeaders(req, t.headers)
	}
	resp, err := t.base.RoundTrip(req)
	if err == nil && t.tr != nil {
		t.tr.observe(resp, nil)
	}
	return resp, err
}

// oauth2FieldsSet names the OAuth2-only fields set on a flow that is not an
// OAuth2 type (lint warns: they do nothing there).
func oauth2FieldsSet(lf *LoginFlow) []string {
	var out []string
	for _, f := range []struct{ name, v string }{
		{"token_url", lf.TokenURL}, {"client_id", lf.ClientID}, {"client_secret", lf.ClientSecret},
		{"scope", lf.Scope}, {"audience", lf.Audience}, {"refresh_token", lf.RefreshToken},
		{"auth_style", lf.AuthStyle},
	} {
		if f.v != "" {
			out = append(out, f.name)
		}
	}
	return out
}

// lintOAuth2Flow checks an OAuth2 login: the fields its grant needs, a usable
// token_url, a known auth_style, and the request-flow fields it ignores.
func lintOAuth2Flow(lf *LoginFlow, prefix string) []LintIssue {
	var issues []LintIssue
	errorf := func(field, format string, args ...any) {
		issues = append(issues, LintIssue{Field: joinField(prefix, field), Severity: "error", Message: fmt.Sprintf(format, args...)})
	}
	warnf := func(field, format string, args ...any) {
		issues = append(issues, LintIssue{Field: joinField(prefix, field), Severity: "warning", Message: fmt.Sprintf(format, args...)})
	}

	if strings.TrimSpace(lf.TokenURL) == "" {
		errorf("token_url", "token_url is required for type %q", lf.Type)
	} else if !strings.Contains(lf.TokenURL, "{{") {
		if u, err := url.Parse(lf.TokenURL); err != nil {
			errorf("token_url", "invalid URL: %v", err)
		} else if u.Scheme != "http" && u.Scheme != "https" {
			errorf("token_url", "URL scheme must be http or https, got %q", u.Scheme)
		}
	}
	switch lf.Type {
	case LoginTypeOAuth2ClientCredentials:
		if strings.TrimSpace(lf.ClientID) == "" {
			errorf("client_id", "client_id is required for type %q", lf.Type)
		}
		if strings.TrimSpace(lf.ClientSecret) == "" {
			errorf("client_secret", "client_secret is required for type %q", lf.Type)
		}
		if lf.RefreshToken != "" {
			warnf("refresh_token", "refresh_token is ignored for type %q", lf.Type)
		}
	case LoginTypeOAuth2RefreshToken:
		if strings.TrimSpace(lf.RefreshToken) == "" {
			errorf("refresh_token", "refresh_token is required for type %q", lf.Type)
		}
		if lf.Audience != "" || lf.Scope != "" {
			warnf("scope", "scope and audience are not sent with the refresh_token grant (the token keeps the scope it was issued with)")
		}
	}
	switch strings.ToLower(strings.TrimSpace(lf.AuthStyle)) {
	case "", OAuth2AuthStyleHeader, OAuth2AuthStyleBody:
	default:
		errorf("auth_style", "unknown auth_style %q (must be %q or %q)", lf.AuthStyle, OAuth2AuthStyleHeader, OAuth2AuthStyleBody)
	}
	if len(lf.Steps) > 0 {
		errorf("steps", "steps cannot be combined with type %q", lf.Type)
	}
	var ignored []string
	for _, f := range []struct {
		name string
		set  bool
	}{
		{"url", lf.URL != ""}, {"method", lf.Method != ""}, {"body", lf.Body != ""},
		{"content_type", lf.ContentType != ""}, {"token_path", lf.TokenPath != ""},
		{"extract", len(lf.Extract) > 0}, {"expect", lf.Expect != nil},
	} {
		if f.set {
			ignored = append(ignored, f.name)
		}
	}
	if len(ignored) > 0 {
		warnf(ignored[0], "%s are ignored for type %q (the token request is built from token_url and the client fields)", strings.Join(ignored, ", "), lf.Type)
	}
	for _, f := range []struct{ name, v string }{
		{"token_url", lf.TokenURL}, {"client_id", lf.ClientID}, {"client_secret", lf.ClientSecret},
		{"scope", lf.Scope}, {"audience", lf.Audience}, {"refresh_token", lf.RefreshToken},
	} {
		issues = append(issues, lintTemplates(f.v, joinField(prefix, f.name))...)
	}
	return issues
}
