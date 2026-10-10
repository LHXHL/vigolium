package postman

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
	"github.com/vigolium/vigolium/pkg/input/formats/internal/multipartform"
	"go.uber.org/zap"
)

// Options contains Postman-specific parsing options.
type Options struct {
	// BaseURL replaces {{baseUrl}}, {{url}}, and similar variables
	BaseURL string

	// Variables maps variable names to values for {{varName}} substitution
	Variables map[string]string
}

// Format implements formats.Format for Postman Collection v2.1.
type Format struct {
	formatOpts  formats.InputFormatOptions
	postmanOpts Options
	stats       Stats
}

// New creates a new Postman Format parser.
func New() *Format {
	return &Format{}
}

var _ formats.Format = &Format{}

// Name returns the format name.
func (f *Format) Name() string {
	return "postman"
}

// SetOptions sets generic format options.
func (f *Format) SetOptions(options formats.InputFormatOptions) {
	f.formatOpts = options
}

// SetPostmanOptions sets Postman-specific options.
func (f *Format) SetPostmanOptions(opts Options) {
	f.postmanOpts = opts
}

// Parse streams a Postman Collection v2.1 JSON file and calls callback for
// each request. The file is read twice — a prescan for the variables and auth
// blocks Postman writes after the items, then the request pass — and only one
// request is decoded at a time (see stream.go).
func (f *Format) Parse(input string, callback formats.ParseReqRespCallback) error {
	fh, err := os.Open(input)
	if err != nil {
		return fmt.Errorf("failed to read postman collection: %w", err)
	}
	defer func() { _ = fh.Close() }()
	return f.ParseReadSeeker(fh, callback)
}

// ParseFromData parses a Postman Collection from raw bytes (no file I/O).
func (f *Format) ParseFromData(data []byte, callback formats.ParseReqRespCallback) error {
	return f.ParseReadSeeker(bytes.NewReader(data), callback)
}

// ParseReadSeeker streams a Postman Collection from rs, which is read twice.
// The prescan validates the whole document, so a malformed collection fails
// before any request reaches the callback.
func (f *Format) ParseReadSeeker(rs io.ReadSeeker, callback formats.ParseReqRespCallback) error {
	plan, err := prescan(rs)
	if err != nil {
		return fmt.Errorf("failed to parse postman collection: %w", err)
	}
	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to rewind postman collection: %w", err)
	}

	w := &walker{
		f:          f,
		vars:       f.buildVariableMap(plan.variables),
		folderAuth: plan.folderAuth,
		callback:   callback,
		stats:      Stats{UnresolvedVariables: map[string]VariableStats{}},
	}
	err = w.stream(rs, plan)
	w.report()
	f.stats = w.stats
	if err != nil {
		return fmt.Errorf("failed to parse postman collection: %w", err)
	}
	return nil
}

// Count returns the number of requests in the collection. It is the parse's
// prescan alone: a token walk that decodes no request.
func (f *Format) Count(input string) (int64, error) {
	fh, err := os.Open(input)
	if err != nil {
		return 0, err
	}
	defer func() { _ = fh.Close() }()

	plan, err := prescan(fh)
	if err != nil {
		return 0, err
	}
	return plan.requests, nil
}

// Stats describes what the last Parse/ParseFromData call could not import.
type Stats struct {
	// Emitted is the number of requests handed to the callback.
	Emitted int
	// Skipped is the number of requests dropped for any reason (an unresolved
	// variable in the URL, an unparseable URL, ...).
	Skipped int
	// UnresolvedVariables maps each {{name}} that had no value to how many
	// requests it affected.
	UnresolvedVariables map[string]VariableStats
}

// VariableStats counts the requests one unresolved variable affected.
type VariableStats struct {
	// Skipped requests could not be built because the variable sits in the URL.
	Skipped int
	// Kept requests were emitted with the literal {{name}} in a header or body.
	Kept int
}

// Stats returns the import statistics of the most recent parse.
func (f *Format) Stats() Stats {
	return f.stats
}

// --- Postman JSON structures ---

type request struct {
	Method string   `json:"method"`
	Header []header `json:"header"`
	Body   *body    `json:"body"`
	URL    urlField `json:"url"`
	Auth   *auth    `json:"auth"`
}

type header struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Disabled bool   `json:"disabled"`
}

type body struct {
	Mode       string       `json:"mode"`
	Raw        string       `json:"raw"`
	URLEncoded []keyValue   `json:"urlencoded"`
	FormData   []formField  `json:"formdata"`
	GraphQL    *graphQLBody `json:"graphql"`
	Options    *bodyOptions `json:"options"`
	Disabled   bool         `json:"disabled"`
}

type bodyOptions struct {
	Raw struct {
		Language string `json:"language"`
	} `json:"raw"`
}

type graphQLBody struct {
	Query string `json:"query"`
	// Variables is a JSON document serialized as a string in Postman exports;
	// some tools write it as an object, which RawMessage also accepts.
	Variables json.RawMessage `json:"variables"`
}

type keyValue struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Disabled bool   `json:"disabled"`
}

// formField is a formdata entry: a text field, or a file (`type: file`) whose
// contents Postman stores only as a local path in `src`.
type formField struct {
	Key         string          `json:"key"`
	Value       string          `json:"value"`
	Type        string          `json:"type"`
	Src         json.RawMessage `json:"src"`
	ContentType string          `json:"contentType"`
	Disabled    bool            `json:"disabled"`
}

type urlField struct {
	Raw      string     `json:"raw"`
	Protocol string     `json:"protocol"`
	Host     []string   `json:"host"`
	Path     []string   `json:"path"`
	Query    []keyValue `json:"query"`
	Variable []keyValue `json:"variable"`
}

// UnmarshalJSON accepts both the object form of a Postman URL and the bare
// string form (`"url": "https://..."`) that v2.0 exports and hand-written
// collections use.
func (u *urlField) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*u = urlField{Raw: s}
		return nil
	}
	type plain urlField
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*u = urlField(p)
	return nil
}

type variable struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// UnmarshalJSON tolerates non-string variable values (numbers, booleans),
// which Postman writes for typed variables.
func (v *variable) UnmarshalJSON(data []byte) error {
	var raw struct {
		Key   string          `json:"key"`
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	v.Key = raw.Key
	v.Value = rawScalar(raw.Value)
	return nil
}

// auth is a Postman auth block, valid at collection, folder and request level.
// Attributes are kept as a key→value map whichever shape the export used:
// v2.1 writes `"bearer": [{"key":"token","value":"..."}]`, v2.0 writes
// `"bearer": {"token": "..."}`.
type auth struct {
	Type  string
	attrs map[string]string
}

func (a *auth) UnmarshalJSON(data []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	if t, ok := m["type"]; ok {
		_ = json.Unmarshal(t, &a.Type)
	}
	a.attrs = map[string]string{}
	block, ok := m[a.Type]
	if !ok {
		return nil
	}
	var list []struct {
		Key   string          `json:"key"`
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(block, &list); err == nil {
		for _, kv := range list {
			a.attrs[kv.Key] = rawScalar(kv.Value)
		}
		return nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(block, &obj); err == nil {
		for k, v := range obj {
			a.attrs[k] = rawScalar(v)
		}
	}
	return nil
}

// rawScalar renders a JSON scalar as the string Postman would substitute.
func rawScalar(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}

// --- Internal methods ---

// buildVariableMap merges collection variables, user-provided variables, and BaseURL.
func (f *Format) buildVariableMap(collectionVars []variable) map[string]string {
	vars := make(map[string]string)

	// Collection-level variables (lowest priority)
	for _, v := range collectionVars {
		vars[v.Key] = v.Value
	}

	// User-provided variables (higher priority)
	for k, v := range f.postmanOpts.Variables {
		vars[k] = v
	}

	// BaseURL override (highest priority for common URL variables)
	if f.postmanOpts.BaseURL != "" {
		vars["baseUrl"] = f.postmanOpts.BaseURL
		vars["base_url"] = f.postmanOpts.BaseURL
		vars["url"] = f.postmanOpts.BaseURL
	}

	return vars
}

var varPattern = regexp.MustCompile(`\{\{([^}]+)\}\}`)

// substitutor resolves {{name}} references for one request and records the
// names it could not resolve.
type substitutor struct {
	vars       map[string]string
	unresolved map[string]struct{}
}

// replace substitutes {{varName}} with values from the variable map. Values
// may themselves reference variables (`baseUrl = {{scheme}}://{{host}}`), so
// substitution repeats a few times until the string stops changing.
func (s *substitutor) replace(in string) string {
	out := in
	for range 5 {
		next := varPattern.ReplaceAllStringFunc(out, func(match string) string {
			key := strings.TrimSpace(match[2 : len(match)-2]) // strip {{ and }}
			if val, ok := s.vars[key]; ok {
				return val
			}
			// For Postman dynamic variables like $randomXxx, use a placeholder
			if strings.HasPrefix(key, "$") {
				return "test"
			}
			return match // keep as-is if unknown
		})
		if next == out {
			break
		}
		out = next
	}
	for _, m := range varPattern.FindAllStringSubmatch(out, -1) {
		s.unresolved[strings.TrimSpace(m[1])] = struct{}{}
	}
	return out
}

// walker carries the per-parse state of one traversal.
type walker struct {
	f        *Format
	vars     map[string]string
	callback formats.ParseReqRespCallback
	stats    Stats
	// folderAuth is the prescan's folder auth by item path.
	folderAuth map[string]*auth
	// skippedForVars counts requests dropped for an unresolved URL variable;
	// the rest of stats.Skipped failed for some other reason.
	skippedForVars int
	// firstErr keeps one example of a non-variable build failure for the summary.
	firstErr error
}

// emit builds one request with the auth in effect for it, records the
// outcome in stats and hands it to the callback. It returns the callback's
// verdict (true when the request was skipped).
func (w *walker) emit(name string, req *request, reqAuth *auth) bool {
	sub := &substitutor{vars: w.vars, unresolved: map[string]struct{}{}}
	rr, urlUnresolved, err := w.f.buildRequest(req, reqAuth, sub)
	if err != nil {
		w.stats.Skipped++
		for v := range urlUnresolved {
			vs := w.stats.UnresolvedVariables[v]
			vs.Skipped++
			w.stats.UnresolvedVariables[v] = vs
		}
		if len(urlUnresolved) > 0 {
			w.skippedForVars++
		} else if w.firstErr == nil {
			w.firstErr = fmt.Errorf("%q: %w", name, err)
		}
		zap.L().Debug("postman: skipping request",
			zap.String("name", name),
			zap.Error(err))
		return true
	}
	for v := range sub.unresolved {
		vs := w.stats.UnresolvedVariables[v]
		vs.Kept++
		w.stats.UnresolvedVariables[v] = vs
	}

	w.stats.Emitted++
	return w.callback(rr)
}

// report warns once per unresolved variable and once for any other skipped
// requests. Losing requests to a missing {{baseUrl}} is the most common way a
// Postman import comes back empty, so it must be visible at the default level.
func (w *walker) report() {
	names := make([]string, 0, len(w.stats.UnresolvedVariables))
	for name := range w.stats.UnresolvedVariables {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		vs := w.stats.UnresolvedVariables[name]
		zap.L().Warn("postman: unresolved variable {{"+name+"}}; define it as a collection variable or supply it to the importer",
			zap.String("variable", name),
			zap.Int("requests_skipped", vs.Skipped),
			zap.Int("requests_kept_with_placeholder", vs.Kept))
	}
	if other := w.stats.Skipped - w.skippedForVars; other > 0 && w.firstErr != nil {
		zap.L().Warn("postman: skipped requests that could not be built",
			zap.Int("requests_skipped", other),
			zap.String("first_error", w.firstErr.Error()))
	}
}

// buildRequest converts a Postman request into an HttpRequestResponse. On
// failure it also reports which unresolved variables sat in the URL, since
// those are what made the request unbuildable.
func (f *Format) buildRequest(req *request, a *auth, sub *substitutor) (*httpmsg.HttpRequestResponse, map[string]struct{}, error) {
	// Build the full URL
	urlSub := &substitutor{vars: sub.vars, unresolved: map[string]struct{}{}}
	fullURL := f.buildURL(req, urlSub)
	for name := range urlSub.unresolved {
		sub.unresolved[name] = struct{}{}
	}
	if len(urlSub.unresolved) > 0 {
		return nil, urlSub.unresolved, fmt.Errorf("unresolved variable(s) in URL %q", fullURL)
	}
	if fullURL == "" {
		return nil, nil, fmt.Errorf("empty URL")
	}

	// Build raw HTTP request
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = "GET"
	}

	// Parse URL to get path and host
	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid URL %q: %w", fullURL, err)
	}
	if parsedURL.Host == "" {
		return nil, nil, fmt.Errorf("URL %q has no host", fullURL)
	}

	// Auth: resolve before the headers so an explicit header can win over it.
	authHeaderName, authHeaderValue, authQuery := resolveAuth(a, sub)
	if authQuery != "" {
		if parsedURL.RawQuery != "" {
			parsedURL.RawQuery += "&"
		}
		parsedURL.RawQuery += authQuery
		fullURL = parsedURL.String()
	}

	path := parsedURL.RequestURI()
	host := parsedURL.Host

	// Build body first: multipart needs to dictate the Content-Type boundary.
	explicitCT := ""
	for _, h := range req.Header {
		if !h.Disabled && strings.EqualFold(h.Key, "Content-Type") {
			explicitCT = sub.replace(h.Value)
		}
	}
	bodyStr, bodyCT := f.buildBody(req.Body, sub, explicitCT)

	// Build headers
	var headerLines []string
	headerLines = append(headerLines, fmt.Sprintf("Host: %s", host))

	hasContentType := false
	hasAuthHeader := false
	for _, h := range req.Header {
		if h.Disabled || h.Key == "" {
			continue
		}
		value := sub.replace(h.Value)
		if strings.EqualFold(h.Key, "Content-Type") {
			if hasContentType {
				continue
			}
			hasContentType = true
			if bodyCT != "" && bodyCTOverrides(value, bodyCT) {
				value = bodyCT
			}
		}
		if strings.EqualFold(h.Key, "Content-Length") || strings.EqualFold(h.Key, "Host") {
			continue // computed below / taken from the URL
		}
		if authHeaderName != "" && strings.EqualFold(h.Key, authHeaderName) {
			hasAuthHeader = true
		}
		headerLines = append(headerLines, fmt.Sprintf("%s: %s", h.Key, value))
	}

	// An explicit header of the same name wins over the inherited auth.
	if authHeaderName != "" && !hasAuthHeader {
		headerLines = append(headerLines, fmt.Sprintf("%s: %s", authHeaderName, authHeaderValue))
	}

	// Add Content-Type if body present but no Content-Type header
	if bodyStr != "" && !hasContentType && bodyCT != "" {
		headerLines = append(headerLines, "Content-Type: "+bodyCT)
	}

	// Add Content-Length for requests with body
	if bodyStr != "" {
		headerLines = append(headerLines, fmt.Sprintf("Content-Length: %d", len(bodyStr)))
	}

	// Assemble raw HTTP request
	var raw strings.Builder
	fmt.Fprintf(&raw, "%s %s HTTP/1.1\r\n", method, path)
	for _, h := range headerLines {
		raw.WriteString(h)
		raw.WriteString("\r\n")
	}
	raw.WriteString("\r\n")
	if bodyStr != "" {
		raw.WriteString(bodyStr)
	}

	rr, err := httpmsg.ParseRawRequestWithURL(raw.String(), fullURL)
	return rr, nil, err
}

// bodyCTOverrides reports whether the Content-Type a body mode produced must
// replace the one the request declared: only for multipart, where the declared
// header usually lacks the boundary the body was written with.
func bodyCTOverrides(declared, generated string) bool {
	if !strings.HasPrefix(generated, "multipart/") {
		return false
	}
	_, params, err := mime.ParseMediaType(declared)
	return err != nil || params["boundary"] == ""
}

// resolveAuth turns a Postman auth block into the header (or query pair) it
// produces. noauth, an unknown type or a nil block produce nothing.
func resolveAuth(a *auth, sub *substitutor) (headerName, headerValue, query string) {
	if a == nil {
		return "", "", ""
	}
	attr := func(k string) string { return sub.replace(a.attrs[k]) }
	switch strings.ToLower(a.Type) {
	case "bearer":
		if tok := attr("token"); tok != "" {
			return "Authorization", "Bearer " + tok, ""
		}
	case "oauth2":
		if tok := attr("accessToken"); tok != "" && !strings.EqualFold(a.attrs["addTokenTo"], "queryParams") {
			prefix := attr("headerPrefix")
			if prefix == "" {
				prefix = "Bearer"
			}
			return "Authorization", prefix + " " + tok, ""
		}
	case "basic":
		user, pass := attr("username"), attr("password")
		if user != "" || pass != "" {
			return "Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)), ""
		}
	case "apikey":
		key, value := attr("key"), attr("value")
		if key == "" {
			return "", "", ""
		}
		if strings.EqualFold(a.attrs["in"], "query") {
			return "", "", url.QueryEscape(key) + "=" + url.QueryEscape(value)
		}
		return key, value, ""
	}
	return "", "", ""
}

// buildURL constructs the full URL from a Postman request's URL field.
//
// url.raw already carries the enabled query parameters (Postman keeps the two
// in sync), so url.query is only merged in when raw has no query of its own;
// appending it unconditionally sent every parameter twice.
func (f *Format) buildURL(req *request, sub *substitutor) string {
	u := &req.URL

	var full string
	if u.Raw != "" {
		full = sub.replace(u.Raw)
	} else {
		// Fallback: construct from host + path
		hostStr := sub.replace(strings.Join(u.Host, "."))
		if hostStr == "" {
			return ""
		}
		if u.Protocol != "" && !strings.Contains(hostStr, "://") {
			hostStr = u.Protocol + "://" + hostStr
		}
		full = hostStr
		if len(u.Path) > 0 {
			full += "/" + sub.replace(strings.Join(u.Path, "/"))
		}
	}

	// Replace path variables like :username with variable values or defaults
	full = f.replacePathVariables(full, u.Variable, sub)

	if !strings.Contains(full, "?") && len(u.Query) > 0 {
		var params []string
		for _, q := range u.Query {
			if q.Disabled {
				continue
			}
			key := sub.replace(q.Key)
			val := sub.replace(q.Value)
			params = append(params, url.QueryEscape(key)+"="+url.QueryEscape(val))
		}
		if len(params) > 0 {
			full += "?" + strings.Join(params, "&")
		}
	}

	// Postman sends scheme-less URLs ("localhost:3000/api") over http.
	if full != "" && !strings.Contains(full, "://") && !varPattern.MatchString(full) {
		full = "http://" + full
	}
	return full
}

// replacePathVariables replaces :paramName path variables with values from
// Postman URL variables or the variable map. Only the path is touched, so a
// `host:port` authority is never mistaken for a variable.
func (f *Format) replacePathVariables(urlStr string, urlVars []keyValue, sub *substitutor) string {
	// Build a lookup from URL-level variables
	varLookup := make(map[string]string)
	for _, v := range urlVars {
		if v.Value != "" {
			varLookup[v.Key] = sub.replace(v.Value)
		}
	}

	query := ""
	if i := strings.IndexAny(urlStr, "?#"); i >= 0 {
		urlStr, query = urlStr[:i], urlStr[i:]
	}

	// Replace :paramName patterns in path segments
	parts := strings.Split(urlStr, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, ":") && len(part) > 1 {
			paramName := part[1:]
			if val, ok := varLookup[paramName]; ok {
				parts[i] = url.PathEscape(val)
			} else if val, ok := sub.vars[paramName]; ok {
				parts[i] = url.PathEscape(val)
			} else {
				parts[i] = "test" // fallback placeholder
			}
		}
	}

	return strings.Join(parts, "/") + query
}

// defaultMultipartBoundary is used for formdata bodies unless the request's
// own Content-Type names one. Fixed rather than random so the same collection
// always yields the same requests (and dedup identities).
const defaultMultipartBoundary = "----VigoliumPostmanBoundary7MA4YWxkTrZu0gW"

// rawLanguageTypes maps Postman's raw body `options.raw.language` to the
// Content-Type Postman itself sends for it.
var rawLanguageTypes = map[string]string{
	"json":       "application/json",
	"xml":        "application/xml",
	"html":       "text/html",
	"javascript": "application/javascript",
	"text":       "text/plain",
}

// buildBody builds the request body and the Content-Type that describes it
// from a Postman body object. explicitCT is the request's own Content-Type
// header, consulted for a multipart boundary.
func (f *Format) buildBody(b *body, sub *substitutor, explicitCT string) (string, string) {
	if b == nil || b.Disabled {
		return "", ""
	}

	switch b.Mode {
	case "raw":
		raw := sub.replace(b.Raw)
		if raw == "" {
			return "", ""
		}
		if b.Options != nil {
			if ct, ok := rawLanguageTypes[strings.ToLower(b.Options.Raw.Language)]; ok {
				return raw, ct
			}
		}
		return raw, sniffRawType(raw)

	case "urlencoded":
		var pairs []string
		for _, kv := range b.URLEncoded {
			if kv.Disabled {
				continue
			}
			key := sub.replace(kv.Key)
			val := sub.replace(kv.Value)
			pairs = append(pairs, url.QueryEscape(key)+"="+url.QueryEscape(val))
		}
		return strings.Join(pairs, "&"), "application/x-www-form-urlencoded"

	case "formdata":
		boundary := defaultMultipartBoundary
		if _, params, err := mime.ParseMediaType(explicitCT); err == nil && params["boundary"] != "" {
			boundary = params["boundary"]
		}
		bodyStr, ct, err := buildMultipart(b.FormData, sub, boundary)
		if err != nil {
			zap.L().Debug("postman: failed to build multipart body", zap.Error(err))
			return "", ""
		}
		return bodyStr, ct

	case "graphql":
		if b.GraphQL == nil {
			return "", ""
		}
		payload := map[string]any{"query": sub.replace(b.GraphQL.Query)}
		if vars := graphQLVariables(b.GraphQL.Variables, sub); vars != nil {
			payload["variables"] = vars
		}
		out, err := json.Marshal(payload)
		if err != nil {
			return "", ""
		}
		return string(out), "application/json"

	default:
		return "", ""
	}
}

// graphQLVariables decodes Postman's graphql.variables, which is normally a
// JSON document serialized as a string. Invalid or empty variables are dropped
// rather than sent as a string the server would reject.
func graphQLVariables(raw json.RawMessage, sub *substitutor) any {
	text := rawScalar(raw)
	if len(raw) > 0 && raw[0] == '{' {
		text = string(raw)
	}
	text = strings.TrimSpace(sub.replace(text))
	if text == "" {
		return nil
	}
	var v any
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		return nil
	}
	return v
}

// sniffRawType picks a Content-Type for a raw body whose language Postman did
// not record.
func sniffRawType(raw string) string {
	t := strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(t, "{"), strings.HasPrefix(t, "["):
		return "application/json"
	case strings.HasPrefix(t, "<"):
		return "application/xml"
	default:
		return "text/plain"
	}
}

// buildMultipart renders formdata entries as a multipart/form-data body. File
// entries become placeholder parts: Postman stores only a local path, never
// the file contents, so the part carries the file name and an empty body.
func buildMultipart(fields []formField, sub *substitutor, boundary string) (string, string, error) {
	parts := make([]multipartform.Part, 0, len(fields))
	for _, fld := range fields {
		if fld.Disabled || fld.Key == "" {
			continue
		}
		part := multipartform.Part{Name: sub.replace(fld.Key), ContentType: fld.ContentType}
		if strings.EqualFold(fld.Type, "file") {
			name := filepath.Base(firstSrc(fld.Src))
			if name == "" || name == "." || name == "/" {
				name = "file.bin"
			}
			part.FileName = name
		} else {
			part.Value = sub.replace(fld.Value)
		}
		parts = append(parts, part)
	}
	return multipartform.Build(parts, boundary)
}

// firstSrc returns the file path of a formdata file entry; `src` is a string
// or, for multi-file fields, an array of strings.
func firstSrc(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil && len(list) > 0 {
		return list[0]
	}
	return ""
}
