package authentication

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// knownTokenFields are JSON field names commonly used for auth tokens, ordered by priority.
var knownTokenFields = []string{
	"token",
	"access_token",
	"accessToken",
	"jwt",
	"id_token",
	"idToken",
	"auth_token",
	"authToken",
	"session_token",
	"sessionToken",
	"bearer",
	"api_token",
	"apiToken",
	"api_key",
	"apiKey",
}

// knownAuthResponseHeaders are response headers that may carry auth tokens.
var knownAuthResponseHeaders = []string{
	"Authorization",
	"X-Auth-Token",
	"X-Access-Token",
	"X-Session-Token",
	"X-Api-Key",
	"X-JWT-Token",
}

// DiscoverResult holds the output of auto-discovery.
type DiscoverResult struct {
	Session      *Session
	StatusCode   int
	TokenSources []string // human-readable descriptions of where tokens were found
	RawResponse  string   // raw response for storage in login_response
}

// DiscoverLogin sends the given login request and auto-discovers auth tokens
// from the response. It checks JSON body fields, Set-Cookie headers, and
// auth response headers. Returns a Session with a LoginFlow populated with
// auto-generated ExtractRules.
func DiscoverLogin(loginReq *LoginRequest) (*DiscoverResult, error) {
	return DiscoverLoginContext(context.Background(), loginReq, nil)
}

// DiscoverLoginContext is DiscoverLogin bounded by ctx and sent over client's
// transport (pkg/http.LoginTransport: the scan's proxy and TLS stance). client
// is copied, never mutated; nil keeps the old direct, certificate-ignoring
// transport.
func DiscoverLoginContext(ctx context.Context, loginReq *LoginRequest, client *http.Client) (*DiscoverResult, error) {
	if loginReq == nil {
		return nil, fmt.Errorf("nil login request")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	if client == nil {
		client = &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}
	}
	client = withLoginJar(client, jar)
	if client.CheckRedirect == nil {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		}
	}

	var body io.Reader
	if loginReq.Body != "" {
		body = strings.NewReader(loginReq.Body)
	}

	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(loginReq.Method), loginReq.URL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Apply headers from the raw request.
	for k, v := range loginReq.Headers {
		if strings.EqualFold(k, "host") {
			continue // Host is set from URL
		}
		req.Header.Set(k, v)
	}

	// Auto-detect content type if not set.
	if req.Header.Get("Content-Type") == "" && loginReq.Body != "" {
		if strings.HasPrefix(strings.TrimSpace(loginReq.Body), "{") {
			req.Header.Set("Content-Type", "application/json")
		} else {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("login request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	result := &DiscoverResult{
		StatusCode: resp.StatusCode,
	}

	// Build raw response for storage.
	var rawResp strings.Builder
	fmt.Fprintf(&rawResp, "%s %s\r\n", resp.Proto, resp.Status)
	for k, vals := range resp.Header {
		for _, v := range vals {
			fmt.Fprintf(&rawResp, "%s: %s\r\n", k, v)
		}
	}
	rawResp.WriteString("\r\n")
	rawResp.Write(respBody)
	result.RawResponse = rawResp.String()

	// Only auto-discover on success responses.
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return result, fmt.Errorf("login returned status %d", resp.StatusCode)
	}

	// Discover tokens from the response.
	extractRules, headers, sources := discoverTokenRules(resp, respBody, resp.Cookies())
	result.TokenSources = append(result.TokenSources, sources...)

	if len(extractRules) == 0 {
		return result, fmt.Errorf("no auth tokens found in response (status %d)", resp.StatusCode)
	}

	// Build the session.
	contentType := loginReq.Headers["Content-Type"]
	if contentType == "" {
		contentType = req.Header.Get("Content-Type")
	}

	sess := &Session{
		Name:    "auto-discovered",
		Role:    RolePrimary,
		Headers: headers,
		Login: &LoginFlow{
			URL:         loginReq.URL,
			Method:      strings.ToUpper(loginReq.Method),
			ContentType: contentType,
			Body:        loginReq.Body,
			Extract:     extractRules,
		},
		LoginRequest: loginReq.Raw,
		hydrated:     true,
	}

	result.Session = sess
	return result, nil
}

// discoverTokenRules derives extract rules from a login response: a known token
// field in a JSON body, the cookies the login set, and known auth response
// headers. It also returns the header values those rules yield on this response
// and a human-readable line per source. cookies is what the login set — the
// response's Set-Cookie, or the flow's jar when redirects were followed.
//
// It is the one definition of "what counts as a token", shared by `auth load`'s
// DiscoverLogin and by a login_request session logging in during a scan, so the
// two cannot disagree about the same request.
func discoverTokenRules(resp *http.Response, body []byte, cookies []*http.Cookie) ([]ExtractRule, map[string]string, []string) {
	var rules []ExtractRule
	var sources []string
	headers := make(map[string]string)

	// 1. JSON body: look for known token fields.
	if isJSONResponse(resp) && len(body) > 0 {
		jsonRules, jsonHeaders := discoverJSONTokens(body)
		rules = append(rules, jsonRules...)
		for k, v := range jsonHeaders {
			headers[k] = v
		}
		for _, r := range jsonRules {
			sources = append(sources, fmt.Sprintf("json body: %s -> %s", r.Path, r.ApplyAs))
		}
	}

	// 2. Cookies set by the login.
	if len(cookies) > 0 {
		cookieRule, cookieHeader := discoverCookieTokens(cookies)
		if cookieRule != nil {
			rules = append(rules, *cookieRule)
			for k, v := range cookieHeader {
				headers[k] = v
			}
			sources = append(sources, fmt.Sprintf("cookies: %d cookie(s)", len(cookies)))
		}
	}

	// 3. Auth response headers.
	for _, hdr := range knownAuthResponseHeaders {
		val := resp.Header.Get(hdr)
		if val == "" {
			continue
		}
		rules = append(rules, ExtractRule{
			Source:  ExtractHeader,
			Name:    hdr,
			ApplyAs: hdr + ": {value}",
		})
		headers[hdr] = val
		sources = append(sources, fmt.Sprintf("header: %s", hdr))
	}

	return rules, headers, sources
}

// loginFlowFromRequest turns a parsed raw login request into a LoginFlow whose
// extract rules are discovered from each login response (see discoverTokenRules)
// rather than configured. The raw request's own headers ride along, except the
// ones the HTTP client derives itself.
func loginFlowFromRequest(lr *LoginRequest) *LoginFlow {
	lf := &LoginFlow{
		URL:            lr.URL,
		Method:         strings.ToUpper(lr.Method),
		Body:           lr.Body,
		discoverTokens: true,
	}
	for k, v := range lr.Headers {
		switch {
		case strings.EqualFold(k, "Content-Type"):
			lf.ContentType = v
		case strings.EqualFold(k, "Host"), strings.EqualFold(k, "Content-Length"):
			// Set by the client from the URL and the body.
		default:
			if lf.headers == nil {
				lf.headers = make(map[string]string)
			}
			lf.headers[k] = v
		}
	}
	return lf
}

// convertLoginRequest gives a session that carries only a raw login_request a
// LoginFlow, so it actually logs in when a scan hydrates its sessions. Before,
// HydrateSessions skipped every session without a Login: a login_request session
// validated, loaded, and then scanned anonymously without a word. A session that
// already has a Login, or no login_request, is left alone.
func (s *Session) convertLoginRequest() error {
	if s.LoginRequest == "" || s.Login != nil {
		return nil
	}
	lr, err := ParseRawLoginRequest(s.LoginRequest)
	if err != nil {
		return fmt.Errorf("session %q: login_request: %w", s.Name, err)
	}
	s.Login = loginFlowFromRequest(lr)
	return nil
}

// LoginRequest holds a parsed raw HTTP login request.
type LoginRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
	Raw     string // original raw request text
}

// ParseRawLoginRequest parses a raw HTTP request string into a LoginRequest.
// Supports the format:
//
//	POST /rest/user/login HTTP/1.1
//	Host: localhost:3000
//	Content-Type: application/json
//
//	{"email":"admin@juice-sh.op","password":"admin123"}
func ParseRawLoginRequest(raw string) (*LoginRequest, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty request")
	}

	reader := bufio.NewReader(strings.NewReader(raw))

	// Parse request line.
	requestLine, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read request line: %w", err)
	}
	requestLine = strings.TrimSpace(requestLine)

	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid request line: %s", requestLine)
	}

	method := parts[0]
	path := parts[1]

	// Parse headers.
	headers := make(map[string]string)
	for {
		line, readErr := reader.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if readErr != nil && readErr != io.EOF {
			break
		}
		idx := strings.Index(line, ":")
		if idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			headers[key] = val
		}
		if readErr == io.EOF {
			break
		}
	}

	// Read body (everything after blank line).
	bodyBytes, _ := io.ReadAll(reader)
	body := strings.TrimSpace(string(bodyBytes))

	// Build full URL from Host header and path.
	host := headers["Host"]
	if host == "" {
		// Try case-insensitive lookup.
		for k, v := range headers {
			if strings.EqualFold(k, "host") {
				host = v
				break
			}
		}
	}
	if host == "" {
		return nil, fmt.Errorf("no Host header found in request")
	}

	// Determine scheme.
	scheme := "https"
	if strings.HasSuffix(host, ":80") || strings.HasPrefix(path, "http://") {
		scheme = "http"
	}

	var fullURL string
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		fullURL = path
	} else {
		fullURL = fmt.Sprintf("%s://%s%s", scheme, host, path)
	}

	// Validate URL.
	if _, urlErr := url.Parse(fullURL); urlErr != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", fullURL, urlErr)
	}

	return &LoginRequest{
		Method:  method,
		URL:     fullURL,
		Headers: headers,
		Body:    body,
		Raw:     raw,
	}, nil
}

// IsRawHTTPRequest returns true if the data looks like a raw HTTP request.
func IsRawHTTPRequest(data []byte) bool {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return false
	}
	// Check first line matches HTTP method + path + version pattern.
	firstLine := trimmed
	if idx := strings.IndexAny(trimmed, "\r\n"); idx > 0 {
		firstLine = trimmed[:idx]
	}
	parts := strings.SplitN(firstLine, " ", 3)
	if len(parts) < 2 {
		return false
	}
	method := parts[0]
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT":
		return strings.HasPrefix(parts[1], "/") || strings.HasPrefix(parts[1], "http")
	}
	return false
}

// discoverJSONTokens looks for known token fields in a JSON response body.
func discoverJSONTokens(body []byte) ([]ExtractRule, map[string]string) {
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, nil
	}

	var rules []ExtractRule
	headers := make(map[string]string)

	// Search top-level fields.
	for _, field := range knownTokenFields {
		if val, ok := data[field]; ok {
			strVal := fmt.Sprintf("%v", val)
			if strVal == "" || strVal == "<nil>" {
				continue
			}
			rule := ExtractRule{
				Source:  ExtractJSON,
				Path:    field,
				ApplyAs: "Authorization: Bearer {value}",
			}
			rules = append(rules, rule)
			headers["Authorization"] = "Bearer " + strVal
			return rules, headers // take the first match
		}
	}

	// Search one level deep (e.g. data.token, authentication.token).
	for parentKey, parentVal := range data {
		nested, ok := parentVal.(map[string]any)
		if !ok {
			continue
		}
		for _, field := range knownTokenFields {
			if val, ok := nested[field]; ok {
				strVal := fmt.Sprintf("%v", val)
				if strVal == "" || strVal == "<nil>" {
					continue
				}
				path := parentKey + "." + field
				rule := ExtractRule{
					Source:  ExtractJSON,
					Path:    path,
					ApplyAs: "Authorization: Bearer {value}",
				}
				rules = append(rules, rule)
				headers["Authorization"] = "Bearer " + strVal
				return rules, headers
			}
		}
	}

	return nil, nil
}

// discoverCookieTokens creates an extract rule for all Set-Cookie values.
func discoverCookieTokens(cookies []*http.Cookie) (*ExtractRule, map[string]string) {
	if len(cookies) == 0 {
		return nil, nil
	}

	// Build Cookie header from all cookies.
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		if c.Value != "" {
			parts = append(parts, c.Name+"="+c.Value)
		}
	}
	if len(parts) == 0 {
		return nil, nil
	}

	rule := &ExtractRule{
		Source: ExtractCookie,
		// Empty Name means "extract all cookies".
	}

	headers := map[string]string{
		"Cookie": strings.Join(parts, "; "),
	}

	return rule, headers
}

// isJSONResponse checks if the response has a JSON content type.
func isJSONResponse(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(ct, "json")
}
