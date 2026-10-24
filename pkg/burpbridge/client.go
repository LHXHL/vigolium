// Package burpbridge provides a read-only client for the loopback HTTP listener
// hosted by the Vigolium Burp extension.
package burpbridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

const (
	DefaultURL          = "http://127.0.0.1:9009"
	EnvironmentVariable = "VIGOLIUM_BURP_BRIDGE_URL"
	// Source is the http_records.source label used when the listener does not
	// say which implementation it is. Every shipped Burp build answers to it,
	// and a listener that reports nothing is treated as Burp, so this is the
	// safe default rather than an arbitrary one.
	Source = database.RecordSourceBurp
	// UUIDPrefix is deliberately vendor-neutral in practice: it is an opaque
	// routing token that says "this record lives behind the bridge, not in the
	// database", not a provenance label. Vendor lives in Source. Making it
	// per-vendor would mean IsBridgeUUID, InspectWithLimit's TrimPrefix, the
	// replay --in-replace guard and the server's inspect handler all growing a
	// prefix set, for a distinction the Source column already carries.
	UUIDPrefix          = "burp:"
	maxResponseBytes    = 16 * 1024 * 1024
	defaultInspectBytes = 64 * 1024
	MaxImportBytes      = 4 * 1024 * 1024
)

// Implementation identities a bridge listener may report, in /health and — as
// of the vendor-labelling change — in every /search and /inspect reply.
const (
	ImplementationBurp  = "vigolium-burp-bridge"
	ImplementationCaido = "vigolium-caido-bridge"
)

// implementationSources is the closed allowlist mapping a reported
// implementation identity to an http_records.source label.
//
// The listener reports what it *is*, never what the source column should say.
// Anything on loopback can answer this protocol, and a listener that could name
// its own source label would be able to claim "scanner" or "finding" — values
// that do not merely mislabel a row but change which records scan-on-receive
// feeds back into a scan (see database.IngestRecordSources). Mapping through a
// fixed table makes an unrecognised identity fall back to Burp instead of
// reaching the database.
var implementationSources = map[string]string{
	ImplementationBurp:  database.RecordSourceBurp,
	ImplementationCaido: database.RecordSourceCaido,
}

// sourceForImplementation resolves a reported implementation identity to a
// record source label. An empty identity means the listener predates the
// change; an unrecognised one means a build newer than this binary or a
// third-party listener. Both answer Burp, which is what every bridge was
// labelled as before, so neither can silently mislabel a row as something the
// scan pipeline treats specially.
func sourceForImplementation(implementation string) string {
	trimmed := strings.TrimSpace(implementation)
	if source, ok := implementationSources[strings.ToLower(trimmed)]; ok {
		return source
	}
	// Debug rather than Warn: against a pre-change Burp jar this is the normal
	// steady state, not a problem. The implementation field distinguishes the
	// two ways of getting here — empty means a listener too old to report one,
	// non-empty means a build newer than this binary or a third-party listener.
	zap.L().Debug("bridge listener reported no recognised implementation; labelling records as Burp",
		zap.String("implementation", trimmed), zap.String("assumed_source", Source))
	return Source
}

type Client struct {
	baseURL string
	http    *http.Client

	// resolvedSource caches the record source label derived from the last
	// implementation identity the listener reported. It exists for the
	// standalone /inspect path: a single-record read (the server's inspect
	// handler, `traffic -u burp:<ref>`) has no preceding /search to learn the
	// vendor from, and a reply that omits the identity would otherwise fall all
	// the way back to Burp. Guarded because one Client is shared across the
	// import loop's concurrent-capable callers.
	mu             sync.RWMutex
	resolvedSource string
}

// rememberSource records the vendor a reply reported. Empty input is ignored so
// a reply that omits the field cannot erase an identity an earlier reply
// established.
func (c *Client) rememberSource(source string) {
	if source == "" {
		return
	}
	c.mu.Lock()
	c.resolvedSource = source
	c.mu.Unlock()
}

// cachedSource returns the last resolved vendor, or the Burp default when no
// reply has reported one yet.
func (c *Client) cachedSource() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.resolvedSource == "" {
		return Source
	}
	return c.resolvedSource
}

type Query struct {
	ProjectUUID   string
	Location      string
	Host          string
	Methods       []string
	Path          string
	StatusCodes   []int
	ContentType   string
	SearchTerms   []string
	ExcludeTerms  []string
	HeaderSearch  string
	BodySearch    string
	ExcludeHeader string
	ExcludeBody   string
	DateFrom      *time.Time
	DateTo        *time.Time
	Limit         int
	Offset        int
	SortBy        string
	SortAsc       bool
	IncludeRaw    bool
}

type Result struct {
	Records []*database.HTTPRecord
	Total   int64
	// Source is the http_records.source label the answering listener resolved
	// to — the same value stamped on every record in Records. Callers that
	// applied a --source filter compare against it, because eligibility has to
	// be decided before the request goes out and therefore cannot know which
	// vendor will answer.
	Source string
}

// Eligible reports whether a database-style filter can include ephemeral bridge
// records. Risk and remark filters are database enrichments that live traffic
// does not have, and neither is scan provenance (--scan-uuid), so those
// queries remain database-only.
//
// A --source filter naming *any* bridge vendor keeps the bridge in play rather
// than only the one this build defaults to. Which vendor is actually listening
// is not knowable until it replies, so narrowing here would mean `--source
// caido` never issuing the query that would have proved the bridge is Caido.
// The post-reply check lives in the caller (see MatchesSourceFilter).
func Eligible(filters database.QueryFilters) bool {
	if filters.Source != "" && !database.IsBridgeRecordSource(filters.Source) {
		return false
	}
	return filters.MinRiskScore == 0 && filters.Remark == "" && len(filters.Remarks) == 0 &&
		filters.ScanUUID == ""
}

// MatchesSourceFilter reports whether live records from a listener that
// resolved to resolvedSource satisfy a --source filter.
//
// The answer is all-or-nothing: one bridge is one vendor, so either every live
// record matches or none do.
func MatchesSourceFilter(filterSource, resolvedSource string) bool {
	if filterSource == "" {
		return true
	}
	if resolvedSource == "" {
		resolvedSource = Source
	}
	return strings.EqualFold(filterSource, resolvedSource)
}

// FilterBySource returns r when its vendor satisfies a --source filter, and an
// empty Result otherwise.
//
// Discarding is a method rather than something each caller writes because
// Records and Total have to go together: MergePage pages over
// localTotal+liveTotal, so a set that is dropped but still counted reports more
// records than it can show. Leaving that to the call site means every caller
// has to rediscover it.
func (r Result) FilterBySource(filterSource string) Result {
	if MatchesSourceFilter(filterSource, r.Source) {
		return r
	}
	return Result{}
}

// QueryFromFilters maps the common traffic filters used by the CLI and REST
// API to the Burp listener protocol.
func QueryFromFilters(filters database.QueryFilters, includeRaw bool) Query {
	searchTerms := append([]string(nil), filters.EffectiveSearchTerms()...)
	if filters.FuzzyTerm != "" {
		searchTerms = append(searchTerms, filters.FuzzyTerm)
	}
	return Query{
		ProjectUUID:   filters.ProjectUUID,
		Location:      "proxy_history",
		Host:          filters.HostPattern,
		Methods:       append([]string(nil), filters.Methods...),
		Path:          filters.PathPattern,
		StatusCodes:   append([]int(nil), filters.StatusCodes...),
		ContentType:   filters.ContentType,
		SearchTerms:   searchTerms,
		ExcludeTerms:  append([]string(nil), filters.EffectiveExcludeTerms()...),
		HeaderSearch:  filters.HeaderSearch,
		BodySearch:    filters.BodySearch,
		ExcludeHeader: filters.ExcludeHeaderSearch,
		ExcludeBody:   filters.ExcludeBodySearch,
		DateFrom:      filters.DateFrom,
		DateTo:        filters.DateTo,
		Limit:         filters.Limit,
		Offset:        filters.Offset,
		SortBy:        filters.SortBy,
		SortAsc:       filters.SortAsc,
		IncludeRaw:    includeRaw,
	}
}

func New(rawURL string) (*Client, error) {
	baseURL, err := ValidateURL(rawURL)
	if err != nil {
		return nil, err
	}
	return &Client{
		baseURL: baseURL,
		http:    &http.Client{Timeout: 30 * time.Second, Transport: bridgeTransport},
	}, nil
}

// bridgeIdleConns is how many idle connections to the bridge are kept. Every
// bridge call goes to one host, and `fuzz --send-via-burp -c N` sends N at
// once; http.DefaultTransport keeps 2, so at -c 10 eight of every ten calls
// dialed a fresh connection and the rest were closed on return.
const bridgeIdleConns = 64

// bridgeTransport is shared by every Client: they all talk to the same
// listener, so one pool serves them.
var bridgeTransport = newBridgeTransport()

func newBridgeTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = bridgeIdleConns
	t.MaxIdleConnsPerHost = bridgeIdleConns
	return t
}

func URLFromEnvironment() string {
	return strings.TrimSpace(os.Getenv(EnvironmentVariable))
}

func ValidateURL(rawURL string) (string, error) {
	value := strings.TrimRight(strings.TrimSpace(rawURL), "/")
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() == "" || parsed.Port() == "" {
		return "", errors.New("burp bridge URL must be an http:// loopback URL with a port")
	}
	host := strings.ToLower(parsed.Hostname())
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", errors.New("burp bridge URL must use a loopback host")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("burp bridge URL must not include a path")
	}
	return value, nil
}

func IsBridgeUUID(uuid string) bool {
	return strings.HasPrefix(uuid, UUIDPrefix)
}

func (c *Client) Query(ctx context.Context, query Query) (Result, error) {
	location := query.Location
	if location == "" {
		location = "proxy_history"
	}
	args := map[string]any{
		"location":       location,
		"host":           query.Host,
		"methods":        query.Methods,
		"path":           query.Path,
		"status":         query.StatusCodes,
		"mime_type":      query.ContentType,
		"search_terms":   query.SearchTerms,
		"exclude_terms":  query.ExcludeTerms,
		"header":         query.HeaderSearch,
		"body":           query.BodySearch,
		"exclude_header": query.ExcludeHeader,
		"exclude_body":   query.ExcludeBody,
		"limit":          query.Limit,
		"offset":         query.Offset,
		"sort":           query.SortBy,
		"order":          map[bool]string{true: "asc", false: "desc"}[query.SortAsc],
	}
	if query.DateFrom != nil {
		args["from"] = query.DateFrom.UTC().Format(time.RFC3339Nano)
	}
	if query.DateTo != nil {
		args["to"] = query.DateTo.UTC().Format(time.RFC3339Nano)
	}

	var response searchResponse
	if err := c.post(ctx, "/api/burp-bridge/search", args, &response); err != nil {
		return Result{}, err
	}
	source := sourceForImplementation(response.Implementation)
	c.rememberSource(source)
	records := make([]*database.HTTPRecord, 0, len(response.Records))
	for _, item := range response.Records {
		record := item.toHTTPRecord(query.ProjectUUID, source)
		if query.IncludeRaw {
			inspection, err := c.InspectWithLimit(ctx, record.UUID, query.ProjectUUID, defaultInspectBytes)
			if err != nil {
				return Result{}, err
			}
			full := inspection.Record
			full.SentAt = record.SentAt
			full.CreatedAt = record.CreatedAt
			full.Remarks = record.Remarks
			record = full
		}
		records = append(records, record)
	}
	total := response.Total
	if total == 0 && len(records) > 0 {
		// Compatibility with listener builds predating the total field.
		total = len(records)
	}
	return Result{Records: records, Total: int64(total), Source: source}, nil
}

func (c *Client) Inspect(ctx context.Context, uuid, projectUUID string) (*database.HTTPRecord, error) {
	inspection, err := c.InspectWithLimit(ctx, uuid, projectUUID, defaultInspectBytes)
	if err != nil {
		return nil, err
	}
	return inspection.Record, nil
}

type Inspection struct {
	Record            *database.HTTPRecord
	RequestTruncated  bool
	ResponseTruncated bool
}

// Source returns the record source label the answering listener resolved to.
func (i Inspection) Source() string {
	if i.Record == nil || i.Record.Source == "" {
		return Source
	}
	return i.Record.Source
}

func (c *Client) InspectWithLimit(ctx context.Context, uuid, projectUUID string, maxBytes int) (Inspection, error) {
	ref := strings.TrimPrefix(uuid, UUIDPrefix)
	if ref == "" || ref == uuid {
		return Inspection{}, fmt.Errorf("invalid Burp bridge record UUID %q", uuid)
	}
	if maxBytes <= 0 || maxBytes > MaxImportBytes {
		maxBytes = MaxImportBytes
	}
	var response inspectResponse
	if err := c.post(ctx, "/api/burp-bridge/inspect", map[string]any{
		"ref": ref, "max_bytes": maxBytes,
	}, &response); err != nil {
		return Inspection{}, err
	}
	rawRequest := []byte(response.Request)
	if response.RequestBase64 != "" {
		var err error
		rawRequest, err = base64.StdEncoding.DecodeString(response.RequestBase64)
		if err != nil {
			return Inspection{}, fmt.Errorf("decode Burp request: %w", err)
		}
	}
	if len(rawRequest) == 0 {
		return Inspection{}, errors.New("burp bridge inspect response did not include a request")
	}
	rr, err := httpmsg.ParseRawRequestWithURL(string(rawRequest), response.URL)
	if err != nil {
		return Inspection{}, fmt.Errorf("parse Burp request: %w", err)
	}
	rawResponse := []byte(response.Response)
	if response.ResponseBase64 != "" {
		var err error
		rawResponse, err = base64.StdEncoding.DecodeString(response.ResponseBase64)
		if err != nil {
			return Inspection{}, fmt.Errorf("decode Burp response: %w", err)
		}
	}
	if len(rawResponse) > 0 {
		rr = rr.WithResponse(httpmsg.NewHttpResponse(rawResponse))
	}
	record := &database.HTTPRecord{}
	if err := record.FromHttpRequestResponse(rr); err != nil {
		return Inspection{}, fmt.Errorf("convert Burp record: %w", err)
	}
	record.UUID = uuid
	record.ProjectUUID = projectUUID
	// The identity is read off this reply when the listener sends one, and
	// falls back to whatever a previous reply on this Client established. That
	// fallback is what makes a standalone inspect — the server's single-record
	// handler, `traffic -u burp:<ref>` — label correctly against a listener too
	// old to echo the field per reply.
	if implementation := strings.TrimSpace(response.Implementation); implementation != "" {
		record.Source = sourceForImplementation(implementation)
		c.rememberSource(record.Source)
	} else {
		record.Source = c.cachedSource()
	}
	return Inspection{
		Record:            record,
		RequestTruncated:  response.RequestTruncated,
		ResponseTruncated: response.ResponseTruncated,
	}, nil
}

func (c *Client) post(ctx context.Context, path string, input, output any) error {
	status, body, err := c.postStatus(ctx, path, input)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("burp bridge HTTP %d: %s", status, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, output); err != nil {
		return fmt.Errorf("decode Burp bridge response: %w", err)
	}
	return nil
}

// postStatus performs the round trip and returns the HTTP status and body
// without treating a non-2xx status as an error, so callers that need to react
// to specific codes (the send/repeater endpoints map 403 → scope block, 429 →
// rate limit) can. Transport failures and oversized bodies are still errors.
func (c *Client) postStatus(ctx context.Context, path string, input any) (int, []byte, error) {
	payload, err := json.Marshal(input)
	if err != nil {
		return 0, nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return 0, nil, fmt.Errorf("burp bridge at %s is unavailable: %w", c.baseURL, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return 0, nil, err
	}
	if len(body) > maxResponseBytes {
		return 0, nil, errors.New("burp bridge response exceeds 2 MiB")
	}
	return response.StatusCode, body, nil
}

// HealthInfo is the subset of the bridge's GET /health report that the send
// paths care about: whether the listener is reachable and whether it will
// refuse out-of-scope targets.
type HealthInfo struct {
	Service string `json:"service"`
	// Implementation says which listener answered. Both vendors report the same
	// `service` on purpose (tooling sniffs it to recognise the protocol), so
	// this is the only field that distinguishes them.
	Implementation        string   `json:"implementation"`
	InScopeOnly           bool     `json:"in_scope_only"`
	SendRespectsInScope   bool     `json:"send_respects_in_scope_only"`
	RepeaterTabsPerMinute int      `json:"repeater_tabs_per_minute"`
	Capabilities          []string `json:"capabilities"`
}

// VendorName is the display name of the answering listener, for user-facing
// messages on the send paths ("Caido bridge is in-scope-only"). Falls back to
// Burp, matching how records are labelled when no identity is reported.
func (h HealthInfo) VendorName() string {
	return VendorNameForSource(sourceForImplementation(h.Implementation))
}

// VendorNameForSource renders a record source label as the vendor's display
// name. Anything that is not a known bridge vendor renders as Burp, so a
// message never names a vendor the protocol does not have.
func VendorNameForSource(source string) string {
	if strings.EqualFold(source, database.RecordSourceCaido) {
		return "Caido"
	}
	return "Burp"
}

// Health probes the listener's GET /health endpoint. It is a cheap preflight for
// the explicit send paths (replay/fuzz --send-via-burp), which want a clear "bridge
// unavailable" error up front rather than one error per request mid-run.
func (c *Client) Health(ctx context.Context) (HealthInfo, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return HealthInfo{}, err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return HealthInfo{}, fmt.Errorf("burp bridge at %s is unavailable: %w", c.baseURL, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return HealthInfo{}, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return HealthInfo{}, fmt.Errorf("burp bridge HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var info HealthInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return HealthInfo{}, fmt.Errorf("decode Burp bridge health: %w", err)
	}
	// /health is only probed by the send preflights, but when it does run it is
	// as authoritative as a search reply — so a later standalone inspect on this
	// Client inherits the vendor it established. Only a reported identity is
	// cached: recording the Burp fallback as though it were resolved would make
	// "nobody said" indistinguishable from "the listener said Burp".
	if strings.TrimSpace(info.Implementation) != "" {
		c.rememberSource(sourceForImplementation(info.Implementation))
	}
	return info, nil
}

type searchResponse struct {
	Total int `json:"total"`
	// Implementation names the listener that answered ("vigolium-burp-bridge",
	// "vigolium-caido-bridge"). Echoed per reply rather than read once from
	// /health so the read path costs no extra round trip; absent on listener
	// builds predating the field, which resolves to Burp.
	Implementation string          `json:"implementation"`
	Records        []recordSummary `json:"records"`
}

type recordSummary struct {
	Ref         string `json:"ref"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	RequestHash string `json:"request_hash"`
	Status      int    `json:"status"`
	MimeType    string `json:"mime_type"`
	Notes       string `json:"notes"`
	Time        string `json:"time"`
}

func (s recordSummary) toHTTPRecord(projectUUID, source string) *database.HTTPRecord {
	parsed, _ := url.Parse(s.URL)
	port := 0
	if parsed != nil {
		port, _ = strconv.Atoi(parsed.Port())
		if port == 0 {
			if parsed.Scheme == "https" {
				port = 443
			} else {
				port = 80
			}
		}
	}
	sentAt := time.Now()
	if value, err := time.Parse(time.RFC3339Nano, s.Time); err == nil {
		sentAt = value
	}
	record := &database.HTTPRecord{
		UUID:                UUIDPrefix + s.Ref,
		ProjectUUID:         projectUUID,
		Method:              s.Method,
		URL:                 s.URL,
		StatusCode:          s.Status,
		HasResponse:         s.Status > 0,
		ResponseContentType: s.MimeType,
		RequestHash:         s.RequestHash,
		Source:              source,
		SentAt:              sentAt,
		CreatedAt:           sentAt,
	}
	if parsed != nil {
		record.Scheme = parsed.Scheme
		record.Hostname = parsed.Hostname()
		record.Port = port
		record.Path = parsed.EscapedPath()
		if record.Path == "" {
			record.Path = "/"
		}
	}
	if s.Notes != "" {
		record.Remarks = []string{s.Notes}
	}
	return record
}

type inspectResponse struct {
	URL string `json:"url"`
	// Implementation mirrors searchResponse.Implementation. Echoing it here too
	// is what lets a standalone inspect — one with no preceding search — label
	// its record correctly.
	Implementation    string `json:"implementation"`
	Request           string `json:"request"`
	Response          string `json:"response"`
	RequestBase64     string `json:"request_base64"`
	ResponseBase64    string `json:"response_base64"`
	RequestTruncated  bool   `json:"request_truncated"`
	ResponseTruncated bool   `json:"response_truncated"`
}
