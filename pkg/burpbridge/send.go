package burpbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/replay"
)

const (
	// MaxSendResponseBytes mirrors the listener's response_base64 cap
	// (MAX_INSPECT_BYTES). The true length is always reported separately in
	// SendResult.ResponseLength.
	MaxSendResponseBytes = 4 * 1024 * 1024
	// DefaultSendTimeout / MaxSendTimeout mirror the listener's send-timeout
	// defaults and hard cap.
	DefaultSendTimeout = 30 * time.Second
	MaxSendTimeout     = 120 * time.Second
)

// ErrScopeBlocked is returned when the listener refuses a target because its
// "In-scope items only" setting is on and the target is out of Burp's scope
// (HTTP 403). Callers can detect it with errors.Is.
var ErrScopeBlocked = errors.New("target is out of Burp scope; disable in-scope-only or add it to Target scope")

// ErrRateLimited is returned when the Repeater route's sliding rate limit is hit
// (HTTP 429). It does not apply to /send.
var ErrRateLimited = errors.New("burp Repeater send limit reached; retry shortly")

// HTTPMode mirrors the listener's http_mode values. The empty string means
// "auto" (let Burp negotiate). Use HTTPModeHTTP1 for request-smuggling / desync
// payloads — auto may negotiate HTTP/2 and reframe them.
type HTTPMode string

const (
	HTTPModeAuto            HTTPMode = "auto"
	HTTPModeHTTP1           HTTPMode = "http1"
	HTTPModeHTTP2           HTTPMode = "http2"
	HTTPModeHTTP2IgnoreALPN HTTPMode = "http2_ignore_alpn"
)

// ParseHTTPMode validates a user-supplied http_mode string. An empty value
// resolves to auto.
func ParseHTTPMode(value string) (HTTPMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto":
		return HTTPModeAuto, nil
	case "http1", "http/1", "http/1.1", "http_1":
		return HTTPModeHTTP1, nil
	case "http2", "http/2", "http_2":
		return HTTPModeHTTP2, nil
	case "http2_ignore_alpn", "http_2_ignore_alpn":
		return HTTPModeHTTP2IgnoreALPN, nil
	default:
		return "", fmt.Errorf("http-mode must be one of auto, http1, http2, http2_ignore_alpn")
	}
}

// SendOptions configures a single Burp-engine send.
type SendOptions struct {
	Mode         HTTPMode
	Timeout      time.Duration
	AddToSiteMap bool
	Source       string // sitemap label when AddToSiteMap is set; default "vigolium-send"
}

// SendResult is the decoded /send reply. A target-side failure (connection
// refused, timeout) is NOT a Go error — it lands here as Sent=false with Error
// set, so per-request outcomes stay uniform when fuzzing.
type SendResult struct {
	Sent              bool
	StatusCode        int
	RawResponse       []byte // decoded response_base64 (head+body, up to 4 MiB)
	ResponseLength    int    // true length reported by the listener
	ResponseTruncated bool
	ElapsedMs         int64
	HTTPMode          string
	AddedToSiteMap    bool
	Error             string
}

type sendResponse struct {
	Sent              int    `json:"sent"`
	StatusCode        int    `json:"status_code"`
	ResponseBase64    string `json:"response_base64"`
	ResponseLength    int    `json:"response_length"`
	ResponseTruncated bool   `json:"response_truncated"`
	ElapsedMs         int64  `json:"elapsed_ms"`
	HTTPMode          string `json:"http_mode"`
	AddedToSiteMap    bool   `json:"added_to_sitemap"`
	Error             string `json:"error"`
}

// Send issues raw request bytes through Burp's own HTTP stack via
// POST /api/burp-bridge/send, so malformed requests (deliberate Content-Length,
// request smuggling, unusual methods) go on the wire byte-for-byte instead of
// being normalised by an ordinary HTTP client. Supply rawURL + rawRequest, or a
// ref from a prior search (rawURL/rawRequest ignored when ref is set).
func (c *Client) Send(ctx context.Context, rawURL, ref string, rawRequest []byte, opts SendOptions) (SendResult, error) {
	args, err := buildSendArgs(rawURL, ref, rawRequest, opts.Mode, opts.Timeout)
	if err != nil {
		return SendResult{}, err
	}
	if opts.AddToSiteMap {
		args["add_to_sitemap"] = true
		source := opts.Source
		if source == "" {
			source = "vigolium-send"
		}
		args["source"] = source
	}

	status, body, err := c.postStatus(ctx, "/api/burp-bridge/send", args)
	if err != nil {
		return SendResult{}, err
	}
	if err := statusError(status, body); err != nil {
		return SendResult{}, err
	}

	var raw sendResponse
	if err := decodeJSON(body, &raw); err != nil {
		return SendResult{}, err
	}
	response, err := decodeResponseBase64(raw.ResponseBase64)
	if err != nil {
		return SendResult{}, err
	}
	return SendResult{
		Sent:              raw.Sent == 1,
		StatusCode:        raw.StatusCode,
		RawResponse:       response,
		ResponseLength:    raw.ResponseLength,
		ResponseTruncated: raw.ResponseTruncated,
		ElapsedMs:         raw.ElapsedMs,
		HTTPMode:          raw.HTTPMode,
		AddedToSiteMap:    raw.AddedToSiteMap,
		Error:             raw.Error,
	}, nil
}

// RepeaterOptions configures staging a request in a Burp Repeater tab.
type RepeaterOptions struct {
	TabName string
	Send    bool // also issue the request through Burp and return the response
	Mode    HTTPMode
	Timeout time.Duration
}

// RepeaterResult reports the staged tab and, when Send was set, the response
// Burp fetched (Burp cannot preload a tab's response pane, so it comes back
// here instead of appearing in the tab).
type RepeaterResult struct {
	Sent        bool // tab staged
	TabName     string
	Executed    bool
	StatusCode  int
	RawResponse []byte
	Error       string
}

type repeaterResponse struct {
	Sent           int    `json:"sent"`
	TabName        string `json:"tab_name"`
	Executed       bool   `json:"executed"`
	StatusCode     int    `json:"status_code"`
	ResponseBase64 string `json:"response_base64"`
	Error          string `json:"error"`
}

// SendToRepeater opens the request (rawURL + rawRequest, or a search ref) in a
// Burp Repeater tab for manual testing. This route is rate-limited to 30 tabs
// per minute; exceeding it returns ErrRateLimited and stages nothing.
func (c *Client) SendToRepeater(ctx context.Context, rawURL, ref string, rawRequest []byte, opts RepeaterOptions) (RepeaterResult, error) {
	args, err := buildSendArgs(rawURL, ref, rawRequest, opts.Mode, opts.Timeout)
	if err != nil {
		return RepeaterResult{}, err
	}
	if tab := sanitizeLabel(opts.TabName, MaxRepeaterTabName); tab != "" {
		args["tab_name"] = tab
	}
	if opts.Send {
		args["send"] = true
	}

	status, body, err := c.postStatus(ctx, "/api/burp-bridge/repeater", args)
	if err != nil {
		return RepeaterResult{}, err
	}
	if err := statusError(status, body); err != nil {
		return RepeaterResult{}, err
	}

	var raw repeaterResponse
	if err := decodeJSON(body, &raw); err != nil {
		return RepeaterResult{}, err
	}
	response, err := decodeResponseBase64(raw.ResponseBase64)
	if err != nil {
		return RepeaterResult{}, err
	}
	return RepeaterResult{
		Sent:        raw.Sent == 1,
		TabName:     raw.TabName,
		Executed:    raw.Executed,
		StatusCode:  raw.StatusCode,
		RawResponse: response,
		Error:       raw.Error,
	}, nil
}

// OrganizerOptions configures storing a request/response pair in Burp's
// Organizer. Notes overrides the default note; Highlight groups a batch by
// colour. When Send is set and no response is supplied, Burp fetches one first.
type OrganizerOptions struct {
	Source    string
	Notes     string
	Highlight string
	Send      bool
	Mode      HTTPMode
	Timeout   time.Duration
}

// OrganizerResult reports what was stored (and the fetched response when Send
// was used).
type OrganizerResult struct {
	Added       int
	HasResponse bool
	Notes       string
	StatusCode  int
	RawResponse []byte
}

type organizerResponse struct {
	Added          int    `json:"added"`
	HasResponse    bool   `json:"has_response"`
	Notes          string `json:"notes"`
	StatusCode     int    `json:"status_code"`
	ResponseBase64 string `json:"response_base64"`
}

// SendToOrganizer stores a request (+ optional response) in Burp's Organizer,
// the one Burp tool that keeps both together and can forward to Repeater. When
// opts.Send is set and rawResponse is empty, Burp issues the request first and
// stores the fetched response.
func (c *Client) SendToOrganizer(ctx context.Context, rawURL, ref string, rawRequest, rawResponse []byte, opts OrganizerOptions) (OrganizerResult, error) {
	args, err := buildSendArgs(rawURL, ref, rawRequest, opts.Mode, opts.Timeout)
	if err != nil {
		return OrganizerResult{}, err
	}
	if len(rawResponse) > 0 {
		if len(rawResponse) > MaxSiteMapMessageBytes {
			return OrganizerResult{}, fmt.Errorf("response exceeds the %d MiB Burp safety limit", MaxSiteMapMessageBytes/(1024*1024))
		}
		args["http_response_base64"] = base64.StdEncoding.EncodeToString(rawResponse)
	}
	if source := sanitizeLabel(opts.Source, MaxOrganizerSource); source != "" {
		args["source"] = source
	}
	if notes := sanitizeLabel(opts.Notes, MaxOrganizerNote); notes != "" {
		args["notes"] = notes
	}
	if opts.Highlight != "" {
		args["highlight"] = strings.ToLower(strings.TrimSpace(opts.Highlight))
	}
	if opts.Send {
		args["send"] = true
	}

	status, body, err := c.postStatus(ctx, "/api/burp-bridge/organizer", args)
	if err != nil {
		return OrganizerResult{}, err
	}
	if err := statusError(status, body); err != nil {
		return OrganizerResult{}, err
	}

	var raw organizerResponse
	if err := decodeJSON(body, &raw); err != nil {
		return OrganizerResult{}, err
	}
	response, err := decodeResponseBase64(raw.ResponseBase64)
	if err != nil {
		return OrganizerResult{}, err
	}
	return OrganizerResult{
		Added:       raw.Added,
		HasResponse: raw.HasResponse,
		Notes:       raw.Notes,
		StatusCode:  raw.StatusCode,
		RawResponse: response,
	}, nil
}

// SummaryFromSend adapts a /send reply into the same *replay.Summary a Go-client
// send would produce, so downstream signal code (replay diff, fuzz gating) is
// transport-agnostic. A target-side failure (SendResult.Error) yields a Summary
// with Error set and Status 0, mirroring the built-in send path.
func SummaryFromSend(r SendResult, excerptCap int) *replay.Summary {
	return replay.SummaryFromRawResponse(r.RawResponse, r.StatusCode, r.ElapsedMs, r.Error, excerptCap)
}

// BridgeSender returns a replay-compatible send closure that routes each request
// through Burp's engine. It is plugged into replay.Options.Sender / fuzz.Job.Sender
// so the exact bytes reach the wire unnormalised. A bridge/transport error (or a
// scope block) surfaces as a *replay.Summary with Error set rather than a panic,
// so a single bad send doesn't abort a fuzzing loop.
func BridgeSender(c *Client, scheme, host string, port int, opts SendOptions, excerptCap int) func(context.Context, []byte) *replay.Summary {
	rawURL := buildTargetURL(scheme, host, port)
	return func(ctx context.Context, raw []byte) *replay.Summary {
		res, err := c.Send(ctx, rawURL, "", raw, opts)
		if err != nil {
			return &replay.Summary{Error: err.Error()}
		}
		return SummaryFromSend(res, excerptCap)
	}
}

// buildSendArgs assembles the shared request body for the send/repeater/organizer
// routes: either a search ref, or an absolute URL plus base64 request bytes.
func buildSendArgs(rawURL, ref string, rawRequest []byte, mode HTTPMode, timeout time.Duration) (map[string]any, error) {
	args := map[string]any{"input_mode": "burp_base64"}
	if strings.TrimSpace(ref) != "" {
		args["ref"] = strings.TrimSpace(ref)
	} else {
		target := strings.TrimSpace(rawURL)
		parsed, err := url.Parse(target)
		if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return nil, errors.New("burp send requires an absolute http or https URL (or a search ref)")
		}
		if len(rawRequest) == 0 {
			return nil, errors.New("burp send requires a raw request (or a search ref)")
		}
		if len(rawRequest) > MaxSiteMapMessageBytes {
			return nil, fmt.Errorf("request exceeds the %d MiB Burp safety limit", MaxSiteMapMessageBytes/(1024*1024))
		}
		args["url"] = target
		args["http_request_base64"] = base64.StdEncoding.EncodeToString(rawRequest)
	}
	if mode != "" && mode != HTTPModeAuto {
		args["http_mode"] = string(mode)
	}
	if timeout > 0 {
		if timeout > MaxSendTimeout {
			timeout = MaxSendTimeout
		}
		args["timeout_ms"] = timeout.Milliseconds()
	}
	return args, nil
}

func buildTargetURL(scheme, host string, port int) string {
	if scheme == "" {
		scheme = "http"
	}
	authority := host
	if port > 0 && !isDefaultPort(scheme, port) {
		authority = host + ":" + strconv.Itoa(port)
	}
	return (&url.URL{Scheme: scheme, Host: authority}).String()
}

func isDefaultPort(scheme string, port int) bool {
	return (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
}

// statusError maps a non-2xx bridge status to a typed error, reusing the
// listener's own message where present.
func statusError(status int, body []byte) error {
	if status >= 200 && status < 300 {
		return nil
	}
	message := strings.TrimSpace(string(body))
	if extracted := extractJSONError(body); extracted != "" {
		message = extracted
	}
	switch status {
	case 403:
		if message == "" {
			return ErrScopeBlocked
		}
		return fmt.Errorf("%w (%s)", ErrScopeBlocked, message)
	case 429:
		if message == "" {
			return ErrRateLimited
		}
		return fmt.Errorf("%w (%s)", ErrRateLimited, message)
	default:
		if message == "" {
			message = strconv.Itoa(status)
		}
		return fmt.Errorf("burp bridge HTTP %d: %s", status, message)
	}
}

func decodeJSON(body []byte, out any) error {
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode Burp bridge response: %w", err)
	}
	return nil
}

// extractJSONError pulls the listener's {"error":"..."} message out of an error
// body; returns "" when the body isn't that shape (e.g. plain text).
func extractJSONError(body []byte) string {
	var payload struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &payload) == nil {
		return strings.TrimSpace(payload.Error)
	}
	return ""
}

func decodeResponseBase64(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode Burp response: %w", err)
	}
	return decoded, nil
}

// sanitizeLabel trims a user-supplied label to a single line and caps its length,
// matching the listener's own sanitisation so a rejected value never reaches it.
func sanitizeLabel(value string, max int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return truncateLabel(value, max)
}

// truncateLabel shortens value to max characters, marking the cut with an
// ellipsis so a reader in Burp can tell a clipped note from a short one.
//
// Counted in RUNES, not bytes: a byte slice at a fixed offset can land in the
// middle of a multi-byte character and produce a note ending in a replacement
// glyph. Failing the whole push because a note is long is the wrong severity —
// the note is metadata attached to evidence, and losing its tail is strictly
// better than losing the evidence — so this never errors.
func truncateLabel(value string, max int) string {
	if max <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= max {
		return strings.TrimSpace(value)
	}
	const ellipsis = "…"
	keep := max - len([]rune(ellipsis))
	if keep < 1 {
		keep = max
		return strings.TrimSpace(string(runes[:keep]))
	}
	return strings.TrimSpace(string(runes[:keep])) + ellipsis
}

// MaxOrganizerNote and MaxRepeaterTabName are the label caps the bridge applies.
// Exported so a caller can say what it is about to clip instead of discovering
// the clip in Burp's UI.
const (
	MaxOrganizerNote   = 200
	MaxOrganizerSource = 80
	MaxRepeaterTabName = 64
)
