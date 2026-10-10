package exttest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

// A fixture file (.http) is an optional block of directive comments, a raw
// HTTP request, a blank line, and a raw HTTP response:
//
//	// expect: {"findings": 1}
//	GET /search?q=x HTTP/1.1
//	Host: example.com
//
//	HTTP/1.1 200 OK
//	Content-Type: text/html
//
//	<html>…</html>
//
// The response starts at the first blank line followed by an HTTP status line,
// so a request body sits between the request headers and that line. LF line
// endings are accepted and become CRLF in the headers; a Content-Length the
// file declares is corrected to the body it actually holds. The response is
// optional (a request-scope passive check needs none).
//
// Directives ("// key: value" or "# key: value", before the request line):
//
//	expect     the expectation as JSON (instead of <case>.expect.json)
//	handler    the one handler to call (scanPerRequest, …)
//	insertion  the insertion point for scanPerInsertionPoint, TYPE:name
//	url        the request's URL origin (default http://<Host header>)
//	match      (mock responses only) a substring the request must contain
type httpFixture struct {
	Directives map[string]string
	Request    []byte
	Response   []byte
}

var (
	reDirective = regexp.MustCompile(`^(?://|#)\s*([A-Za-z_-]+)\s*:\s*(.*)$`)
	// reResponseStart finds the blank line that precedes the response's
	// status line.
	reResponseStart = regexp.MustCompile(`\r?\n\r?\n(HTTP/\d(?:\.\d)? \d{3})`)
	reContentLength = regexp.MustCompile(`(?im)^content-length:[^\r\n]*\r$`)
)

// parseHTTPFixture splits a .http fixture into directives, request and
// response.
func parseHTTPFixture(data []byte) (*httpFixture, error) {
	fx := &httpFixture{Directives: map[string]string{}}
	text := string(data)

	// Leading directive and comment lines.
	for {
		line, rest, found := strings.Cut(text, "\n")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" && found {
			text = rest
			continue
		}
		if !strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "#") {
			break
		}
		if m := reDirective.FindStringSubmatch(trimmed); m != nil {
			fx.Directives[strings.ToLower(m[1])] = strings.TrimSpace(m[2])
		}
		if !found {
			text = ""
			break
		}
		text = rest
	}
	if strings.TrimSpace(text) == "" {
		return nil, fmt.Errorf("no HTTP request in fixture")
	}

	reqPart, respPart := text, ""
	if loc := reResponseStart.FindStringSubmatchIndex(text); loc != nil {
		reqPart, respPart = text[:loc[0]], text[loc[2]:]
	}
	fx.Request = normalizeMessage(reqPart)
	if respPart != "" {
		fx.Response = normalizeMessage(respPart)
	}
	return fx, nil
}

// normalizeMessage turns the head of an HTTP message into CRLF lines ending
// with a blank line, and fixes a declared Content-Length to the body's size.
func normalizeMessage(msg string) []byte {
	head, body := msg, ""
	if i := strings.Index(msg, "\r\n\r\n"); i >= 0 {
		head, body = msg[:i], msg[i+4:]
	} else if i := strings.Index(msg, "\n\n"); i >= 0 {
		head, body = msg[:i], msg[i+2:]
	}
	head = strings.TrimRight(head, "\r\n")
	lines := strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n")
	var b bytes.Buffer
	for _, l := range lines {
		b.WriteString(strings.TrimRight(l, "\r"))
		b.WriteString("\r\n")
	}
	headStr := reContentLength.ReplaceAllString(b.String(), "Content-Length: "+strconv.Itoa(len(body))+"\r")
	return []byte(headStr + "\r\n" + body)
}

// requestResponse builds the message a case runs against. origin overrides
// the URL origin (scheme://host[:port]); empty uses the url directive or
// http://<Host header>.
func (fx *httpFixture) requestResponse(origin string) (*httpmsg.HttpRequestResponse, error) {
	if origin == "" {
		origin = fx.Directives["url"]
	}
	req := httpmsg.NewHttpRequest(fx.Request)
	if origin == "" {
		host := req.Header("Host")
		if host == "" {
			return nil, fmt.Errorf("request has no Host header; add one or a // url: directive")
		}
		origin = "http://" + host
	}
	svc, err := httpmsg.ParseService(origin)
	if err != nil {
		return nil, fmt.Errorf("bad url %q: %w", origin, err)
	}
	req = httpmsg.NewHttpRequestWithService(svc, fx.Request)
	var resp *httpmsg.HttpResponse
	if len(fx.Response) > 0 {
		resp = httpmsg.NewHttpResponse(fx.Response)
	}
	return httpmsg.NewHttpRequestResponse(req, resp), nil
}

// withHost rewrites the request's Host header to host (the mock's address).
func withHost(raw []byte, host string) []byte {
	head, body, _ := bytes.Cut(raw, []byte("\r\n\r\n"))
	lines := strings.Split(string(head), "\r\n")
	replaced := false
	for i := 1; i < len(lines); i++ {
		if name, _, ok := strings.Cut(lines[i], ":"); ok && strings.EqualFold(strings.TrimSpace(name), "host") {
			lines[i] = "Host: " + host
			replaced = true
		}
	}
	if !replaced && len(lines) > 0 {
		lines = append(lines[:1], append([]string{"Host: " + host}, lines[1:]...)...)
	}
	return []byte(strings.Join(lines, "\r\n") + "\r\n\r\n" + string(body))
}

// Expectation is what a case must produce: <case>.expect.json, or the
// `// expect:` directive.
type Expectation struct {
	// Findings is a count, or a list each result must match (in any order,
	// and the counts must agree).
	Findings *FindingsExpectation `json:"findings"`
	// Errors is how many handler calls may fail (default 0).
	Errors *int `json:"errors,omitempty"`
	// NetworkCallsBlocked, when set, is how many requests an offline case
	// must have refused.
	NetworkCallsBlocked *int64 `json:"network_calls_blocked,omitempty"`
	// MockRequests, when set, is how many requests the mock must have served.
	MockRequests *int `json:"mock_requests,omitempty"`
	// Handler and Insertion override the directives of the same name.
	Handler   string `json:"handler,omitempty"`
	Insertion string `json:"insertion,omitempty"`
}

// FindingsExpectation is a count or a list of finding matchers.
type FindingsExpectation struct {
	Count    int
	Matchers []FindingMatcher
	isList   bool
}

// FindingMatcher matches one result. "name~" is a case-insensitive
// substring of the finding name, "name" the whole name (case-insensitive);
// severity and confidence compare case-insensitively. Empty fields match
// anything.
type FindingMatcher struct {
	Name         string `json:"name,omitempty"`
	NameContains string `json:"name~,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Confidence   string `json:"confidence,omitempty"`
}

// UnmarshalJSON accepts a number or an array of matchers.
func (f *FindingsExpectation) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '[' {
		f.isList = true
		if err := json.Unmarshal(b, &f.Matchers); err != nil {
			return err
		}
		f.Count = len(f.Matchers)
		return nil
	}
	return json.Unmarshal(b, &f.Count)
}

// MarshalJSON renders the form it was given.
func (f FindingsExpectation) MarshalJSON() ([]byte, error) {
	if f.isList {
		return json.Marshal(f.Matchers)
	}
	return json.Marshal(f.Count)
}

func (m FindingMatcher) matches(r *output.ResultEvent) bool {
	if m.Name != "" && !strings.EqualFold(m.Name, r.Info.Name) {
		return false
	}
	if m.NameContains != "" && !strings.Contains(strings.ToLower(r.Info.Name), strings.ToLower(m.NameContains)) {
		return false
	}
	if m.Severity != "" && !strings.EqualFold(m.Severity, r.Info.Severity.String()) {
		return false
	}
	if m.Confidence != "" && !strings.EqualFold(m.Confidence, r.Info.Confidence.String()) {
		return false
	}
	return true
}

func (m FindingMatcher) String() string {
	var parts []string
	if m.Name != "" {
		parts = append(parts, "name="+strconv.Quote(m.Name))
	}
	if m.NameContains != "" {
		parts = append(parts, "name~"+strconv.Quote(m.NameContains))
	}
	if m.Severity != "" {
		parts = append(parts, "severity="+m.Severity)
	}
	if m.Confidence != "" {
		parts = append(parts, "confidence="+m.Confidence)
	}
	if len(parts) == 0 {
		return "{any}"
	}
	return "{" + strings.Join(parts, " ") + "}"
}

// parseExpectation decodes an expectation, rejecting unknown keys so a typo
// cannot silently expect nothing.
func parseExpectation(data []byte) (*Expectation, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var e Expectation
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("bad expectation: %w", err)
	}
	if e.Findings == nil {
		return nil, fmt.Errorf("bad expectation: \"findings\" is required (a count or a list of {name~, severity, confidence})")
	}
	return &e, nil
}

// check compares what a case produced with e and returns every mismatch.
func (e *Expectation) check(results []*output.ResultEvent, errs int, blocked int64, mockRequests int) []string {
	var failures []string
	if e.Findings != nil {
		if len(results) != e.Findings.Count {
			failures = append(failures, fmt.Sprintf("expected %d finding(s), got %d%s",
				e.Findings.Count, len(results), namesSuffix(results)))
		} else if e.Findings.isList {
			used := make([]bool, len(results))
			for _, m := range e.Findings.Matchers {
				found := false
				for i, r := range results {
					if !used[i] && m.matches(r) {
						used[i], found = true, true
						break
					}
				}
				if !found {
					failures = append(failures, fmt.Sprintf("no finding matches %s%s", m, namesSuffix(results)))
				}
			}
		}
	}
	wantErrs := 0
	if e.Errors != nil {
		wantErrs = *e.Errors
	}
	if errs != wantErrs {
		failures = append(failures, fmt.Sprintf("expected %d handler error(s), got %d", wantErrs, errs))
	}
	if e.NetworkCallsBlocked != nil && blocked != *e.NetworkCallsBlocked {
		failures = append(failures, fmt.Sprintf("expected %d blocked network call(s), got %d", *e.NetworkCallsBlocked, blocked))
	}
	if e.MockRequests != nil && mockRequests != *e.MockRequests {
		failures = append(failures, fmt.Sprintf("expected %d mock request(s), got %d", *e.MockRequests, mockRequests))
	}
	return failures
}

func namesSuffix(results []*output.ResultEvent) string {
	if len(results) == 0 {
		return ""
	}
	names := make([]string, 0, len(results))
	for _, r := range results {
		names = append(names, fmt.Sprintf("%q (%s/%s)", r.Info.Name, r.Info.Severity, r.Info.Confidence))
	}
	return ": " + strings.Join(names, ", ")
}
