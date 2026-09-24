package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/pkg/olium/stream"
)

const openAIChatCompletionsURL = "https://api.openai.com/v1/chat/completions"

// OpenAI is the Chat Completions API provider. It streams Server-Sent Events,
// reassembles tool-call argument deltas, and emits unified stream.Event
// values. Modeled after the Anthropic provider so the engine doesn't need to
// know which backend is running.
//
// The same struct also backs the openai-compatible provider (Ollama,
// OpenRouter, LM Studio, vLLM, etc.) — the only differences are baseURL,
// optional extra headers, and that an empty apiKey suppresses the
// Authorization header so unauthenticated local servers work.
type OpenAI struct {
	apiKey  secret
	baseURL string // full chat-completions URL
	// altURL is baseURL with its /v1 segment toggled, tried once if baseURL
	// 404s. Empty for the canonical OpenAI provider, whose URL is not a guess.
	altURL       string
	extraHeaders map[string]string
	extraBody    map[string]any // merged into every request body; nil = no-op
	name         string
	client       *http.Client
}

// settledEndpoints remembers which spelling of a base URL actually answered,
// keyed by the normalized URL. Process-wide rather than a field, because
// providers are not long-lived: pkg/agent mints a fresh one per engine build
// (per skill, per RunPrompt, per guardrail), so a per-instance latch would
// re-probe every session. Keeping it here also leaves the provider immutable
// after construction, like every other provider in this package.
var settledEndpoints sync.Map // normalized base URL -> the URL that answered

// streamOptionsRejected remembers base URLs whose server refused
// stream_options (see rejectsStreamOptions), so the retry without it is paid
// once per process. Process-wide for the same reason as settledEndpoints.
var streamOptionsRejected sync.Map // normalized base URL -> struct{}

// NewOpenAI constructs the canonical OpenAI provider pointed at
// api.openai.com. The key is wrapped in a formatter-safe secret so a stray
// `%v` on the provider can't leak it.
func NewOpenAI(apiKey string) *OpenAI {
	return &OpenAI{
		apiKey:  secret(apiKey),
		baseURL: openAIChatCompletionsURL,
		name:    "openai",
		client:  newHTTPClient(),
	}
}

// NewOpenAICompatible constructs a provider that speaks the OpenAI Chat
// Completions wire format against an arbitrary endpoint (Ollama, OpenRouter,
// LM Studio, vLLM, Together, Groq, LocalAI, custom proxies).
//
// baseURL accepts either a full chat-completions URL
// (http://host/v1/chat/completions) or the v1 root (http://host/v1), in
// which case /chat/completions is appended. An empty apiKey suppresses the
// Authorization header — required for unauthenticated local servers like
// Ollama. extraHeaders are applied after standard headers so callers can
// override Authorization for backends with non-Bearer schemes.
//
// extraBody is a generic JSON-body extension merged into every outgoing
// request after the typed oaiRequest is marshaled. The five reserved keys
// (model, messages, tools, stream, stream_options) trigger a request-time
// error. Pass nil to disable.
func NewOpenAICompatible(baseURL, apiKey string, extraHeaders map[string]string, extraBody map[string]any) *OpenAI {
	normalized := normalizeOpenAIBaseURL(baseURL)
	return &OpenAI{
		apiKey:       secret(apiKey),
		baseURL:      normalized,
		altURL:       altOpenAIBaseURL(normalized),
		extraHeaders: extraHeaders,
		extraBody:    extraBody,
		name:         "openai-compatible",
		client:       newHTTPClient(),
	}
}

// normalizeOpenAIBaseURL tolerates a full chat-completions URL, a version
// root, or a bare host, resolving each to a complete endpoint. Trailing
// slashes are trimmed so we don't end up with `/v1//chat/...`.
//
// A bare host gets /v1 as well as /chat/completions. It used to get only
// /chat/completions, so `config set ... base_url http://127.0.0.1:8317/`
// (the same server that works when written `.../v1`) POSTed to the host root
// and came back 404.
func normalizeOpenAIBaseURL(raw string) string {
	return normalizeProviderBaseURL(raw, openAIChatEndpoint)
}

// altOpenAIBaseURL returns the same endpoint with its /v1 segment toggled, or
// "" when the URL isn't shaped like a chat-completions endpoint. It is what
// makes the /v1 in normalizeOpenAIBaseURL a guess rather than a verdict:
// openai-compatible servers disagree about whether they mount the API at the
// root or under /v1, the operator shouldn't have to know which, and the URL
// text doesn't say — only a request finds out.
func altOpenAIBaseURL(u string) string {
	return toggleVersionSegment(u, openAIChatEndpoint)
}

// reservedOpenAIBodyKeys are top-level JSON body fields owned by the typed
// oaiRequest. extra_body is not allowed to set them — accidentally
// shadowing `model` or `messages` would silently break the request. The
// merge step returns a clear error instead.
//
// Keep this set in sync with the json tags on oaiRequest below.
var reservedOpenAIBodyKeys = map[string]struct{}{
	"model":          {},
	"messages":       {},
	"tools":          {},
	"stream":         {},
	"stream_options": {},
}

// mergeExtraBody overlays extra onto the marshaled typed payload by
// JSON-round-tripping through a map. Keys in reservedOpenAIBodyKeys are
// rejected with a clear error. A nil/empty extra is a no-op (returns
// payload unchanged). Cost is one extra unmarshal + marshal per request,
// negligible against an LLM round-trip.
func mergeExtraBody(payload []byte, extra map[string]any) ([]byte, error) {
	if len(extra) == 0 {
		return payload, nil
	}
	for k := range extra {
		if _, reserved := reservedOpenAIBodyKeys[k]; reserved {
			return nil, fmt.Errorf("custom_provider.extra_body key %q is reserved (owned by the typed request body — remove it from your config)", k)
		}
	}
	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, fmt.Errorf("merge extra_body: re-decode typed payload: %w", err)
	}
	for k, v := range extra {
		body[k] = v
	}
	out, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("merge extra_body: re-encode: %w", err)
	}
	return out, nil
}

func (o *OpenAI) Name() string {
	if o.name != "" {
		return o.name
	}
	return "openai"
}

// CloseIdleConnections drops idle HTTP/2 conns on this provider's transport.
// See provider.ConnectionResetter.
func (o *OpenAI) CloseIdleConnections() {
	o.client.CloseIdleConnections()
}

// --- Request body types ---

type oaiToolDef struct {
	Type     string         `json:"type"` // always "function"
	Function oaiFunctionDef `json:"function"`
}

type oaiFunctionDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters"`
}

type oaiToolCall struct {
	ID       string          `json:"id,omitempty"`
	Type     string          `json:"type,omitempty"` // "function"
	Function oaiFunctionCall `json:"function"`
}

type oaiFunctionCall struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments"` // JSON-encoded as a string
}

// Content is deliberately NOT omitempty: an assistant turn that carries only
// tool calls has empty text, and strict openai-compatible gateways (Open
// WebUI's OpenAIChatCompletionForm, several pydantic-validated proxies)
// reject a message with no `content` key outright ("messages.N.content Field
// required"), failing the run on the first tool-using turn. OpenAI itself
// accepts "" there.
type oaiMessage struct {
	Role       string        `json:"role"`
	Content    string        `json:"content"`
	ToolCalls  []oaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"`
	Name       string        `json:"name,omitempty"`
}

// oaiRequest is the wire shape of the OpenAI Chat Completions request body.
//
// INVARIANT: every json tag on this struct must appear in
// reservedOpenAIBodyKeys (declared next to mergeExtraBody). The reserved
// set is what prevents custom_provider.extra_body from silently overriding
// typed fields. When you add a field here, update reservedOpenAIBodyKeys
// in lockstep — otherwise extra_body becomes a footgun.
type oaiRequest struct {
	Model    string       `json:"model"`
	Messages []oaiMessage `json:"messages"`
	Tools    []oaiToolDef `json:"tools,omitempty"`
	Stream   bool         `json:"stream"`
	// StreamOptions.IncludeUsage requests the final chunk to carry token
	// counts in `usage` — Anthropic gives them by default; OpenAI requires
	// the opt-in.
	StreamOptions *oaiStreamOptions `json:"stream_options,omitempty"`
}

type oaiStreamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

// Stream issues a streaming Chat Completions request and returns a channel
// of unified events. Same protocol contract as Provider.Stream on every
// other backend in this package.
func (a *OpenAI) Stream(ctx context.Context, req Request) (<-chan stream.Event, error) {
	body := buildOpenAIRequest(req)
	if _, rejected := streamOptionsRejected.Load(a.baseURL); rejected {
		body.StreamOptions = nil
	}
	payload, err := a.encode(body)
	if err != nil {
		return nil, err
	}

	endpoint, alt := a.endpoints()

	resp, err := a.post(ctx, endpoint, payload)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", a.Name(), err)
	}
	// A 404 means the endpoint isn't where the base_url said, which for an
	// openai-compatible server is nearly always the /v1 question altOpenAIBaseURL
	// describes. Try the other spelling once and keep whichever answered. 405
	// counts too: a catch-all static mount (Open WebUI) refuses a POST to an
	// unknown path with 405 rather than 404.
	var alsoTried string
	if isMissingEndpoint(resp.StatusCode) && alt != "" {
		altResp, altErr := a.post(ctx, alt, payload)
		switch {
		case altErr != nil:
			// The alternate is our guess, not the operator's URL; report the
			// 404 they can act on rather than a connection error against a URL
			// they never typed. resp still holds it.
		case !isMissingEndpoint(altResp.StatusCode):
			// The alternate exists - it answered, even if with an error (bad
			// key, unknown model, rate limit, 5xx). Settle on it and report
			// its answer. Settling on the configured URL here pinned the
			// dead spelling for the whole process, so every later request,
			// including the retry of a 429, 404'd with no fallback.
			drainAndClose(resp.Body)
			a.settle(alt)
			resp = altResp
		default:
			// Neither spelling is mounted: a genuinely missing endpoint. Report
			// the alternate's status (same 404 either way in practice) and name
			// what else was tried, so the message isn't a bare "404:".
			drainAndClose(resp.Body)
			a.settle(endpoint)
			resp, alsoTried = altResp, alt
		}
	}
	if resp.StatusCode != http.StatusOK {
		raw := readErrorBody(resp.Body)
		if body.StreamOptions != nil && rejectsStreamOptions(resp.StatusCode, raw) {
			if retry := a.retryWithoutStreamOptions(ctx, body); retry != nil {
				return a.streamBody(ctx, retry), nil
			}
		}
		err := responsesErrorFrom(a.Name(), resp.StatusCode, raw)
		if alsoTried != "" {
			return nil, fmt.Errorf("%w (also tried %s)", err, alsoTried)
		}
		return nil, err
	}
	return a.streamBody(ctx, resp), nil
}

// encode marshals the typed request and overlays extra_body.
func (a *OpenAI) encode(body oaiRequest) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	payload, err = mergeExtraBody(payload, a.extraBody)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", a.Name(), err)
	}
	return payload, nil
}

// retryWithoutStreamOptions resends body without stream_options after a
// strict validator (Mistral, older Groq/LM Studio/Azure) rejected the field,
// which otherwise fails every request. On success the server is remembered
// so later requests omit it up front; the cost is losing streamed usage
// counts. Returns nil when the retry did not produce a 200.
func (a *OpenAI) retryWithoutStreamOptions(ctx context.Context, body oaiRequest) *http.Response {
	body.StreamOptions = nil
	payload, err := a.encode(body)
	if err != nil {
		return nil
	}
	endpoint, _ := a.endpoints()
	resp, err := a.post(ctx, endpoint, payload)
	if err != nil {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		drainAndClose(resp.Body)
		return nil
	}
	streamOptionsRejected.Store(a.baseURL, struct{}{})
	return resp
}

// isMissingEndpoint reports whether a status means "nothing is mounted at
// this path" for the /v1 alternate-spelling probe.
func isMissingEndpoint(status int) bool {
	return status == http.StatusNotFound || status == http.StatusMethodNotAllowed
}

// streamBody starts consuming a 200 response: as SSE normally, or as a
// single JSON completion when the server ignored stream:true.
func (a *OpenAI) streamBody(ctx context.Context, resp *http.Response) <-chan stream.Event {
	out := make(chan stream.Event, 32)
	// Sniff inside the goroutine: the first byte of a stream can take minutes
	// (model load, long prompt processing), and Stream must not block on it.
	go func() {
		body, isJSON := sniffJSONBody(resp.Body)
		if isJSON {
			a.consumeJSON(body, out)
			return
		}
		a.consumeSSE(ctx, body, out)
	}()
	return out
}

// endpoints returns the URL to POST to and the one-shot alternate spelling to
// try if it 404s ("" once the question is settled, or for canonical OpenAI).
func (a *OpenAI) endpoints() (string, string) {
	if a.baseURL == "" {
		return openAIChatCompletionsURL, ""
	}
	if settled, ok := settledEndpoints.Load(a.baseURL); ok {
		return settled.(string), ""
	}
	return a.baseURL, a.altURL
}

// settle records the URL that answered, so the /v1 probe is paid once per
// process rather than once per provider. Recording the configured URL after a
// failed probe matters as much as recording a winner: without it, a genuinely
// missing endpoint costs two requests on every turn instead of one.
func (a *OpenAI) settle(winner string) {
	settledEndpoints.Store(a.baseURL, winner)
}

// post issues one chat-completions request. Split out of Stream so the /v1
// fallback replays the exact same headers and body against the alternate URL
// — a second hand-built request is a second place for the Authorization
// conditional or the extra headers to drift.
func (a *OpenAI) post(ctx context.Context, endpoint string, payload []byte) (*http.Response, error) {
	// Provider tracing (--debug / VIGOLIUM_OLIUM_DEBUG): dump the outgoing
	// request so operators can see the exact model + messages on the wire.
	// The API key lives in the Authorization header (not the body), and
	// debugFprintf scrubs any credential-shaped substrings regardless.
	if DebugEnabled() {
		debugFprintf(os.Stderr, "[%s-req] POST %s %s", a.Name(), endpoint, string(payload))
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	// Skip Authorization when no key is configured — unauthenticated local
	// servers (Ollama, LM Studio with no token, vLLM behind a trust boundary)
	// reject the bogus `Bearer ` value, and the standard OpenAI path always
	// has a key, so the conditional only kicks in for openai-compatible.
	if key := a.apiKey.Reveal(); key != "" {
		httpReq.Header.Set("Authorization", "Bearer "+key)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	for k, v := range a.extraHeaders {
		httpReq.Header.Set(k, v)
	}
	return a.client.Do(httpReq)
}

func buildOpenAIRequest(req Request) oaiRequest {
	messages := make([]oaiMessage, 0, len(req.Messages)+1)
	if req.System != "" {
		messages = append(messages, oaiMessage{Role: "system", Content: req.System})
	}

	for _, m := range req.Messages {
		switch m.Role {
		case RoleUser:
			messages = append(messages, oaiMessage{Role: "user", Content: m.Text})

		case RoleAssistant:
			msg := oaiMessage{Role: "assistant", Content: m.Text}
			if len(m.ToolCalls) > 0 {
				msg.ToolCalls = make([]oaiToolCall, 0, len(m.ToolCalls))
				for _, tc := range m.ToolCalls {
					// A nil map marshals to "null", which is not a JSON
					// object; strict servers reject it as arguments.
					args := tc.Args
					if args == nil {
						args = map[string]any{}
					}
					argsJSON, _ := json.Marshal(args)
					msg.ToolCalls = append(msg.ToolCalls, oaiToolCall{
						ID:   tc.ID,
						Type: "function",
						Function: oaiFunctionCall{
							Name:      tc.Name,
							Arguments: string(argsJSON),
						},
					})
				}
			}
			messages = append(messages, msg)

		case RoleTool:
			messages = append(messages, oaiMessage{
				Role:       "tool",
				ToolCallID: m.ToolCallID,
				Content:    m.Content,
			})
		}
	}

	body := oaiRequest{
		Model:         req.Model,
		Messages:      messages,
		Stream:        true,
		StreamOptions: &oaiStreamOptions{IncludeUsage: true},
	}
	if len(req.Tools) > 0 {
		body.Tools = make([]oaiToolDef, 0, len(req.Tools))
		for _, t := range req.Tools {
			body.Tools = append(body.Tools, oaiToolDef{
				Type: "function",
				Function: oaiFunctionDef{
					Name:        t.Name,
					Description: t.Description,
					Parameters:  t.Schema,
				},
			})
		}
	}
	return body
}

// --- SSE consumption ---

// consumeSSE walks the OpenAI streaming response and emits unified events.
// The protocol differs from Anthropic in three notable ways: (1) the
// terminating sentinel is the literal string `[DONE]`, not a JSON event;
// (2) tool calls are streamed as a list keyed by `index`, with name/id
// arriving once and `function.arguments` arriving as JSON string fragments
// that must be concatenated before parsing; (3) usage stats are only
// included when StreamOptions.IncludeUsage is set, and arrive in a final
// chunk that has an empty `choices` array.
func (a *OpenAI) consumeSSE(ctx context.Context, body io.ReadCloser, out chan<- stream.Event) {
	defer func() { _ = body.Close() }()
	defer close(out)

	reader := stream.NewSSEReader(body)
	state := &openaiState{}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		evt, err := reader.Next()
		if errors.Is(err, io.EOF) {
			// EOF is only a clean end if the stream actually terminated: the
			// `[DONE]` sentinel, or a finish_reason (which sentinel-less
			// gateways still send). Without either, the connection was cut
			// mid-response - flushing here would hand the engine a truncated
			// turn that looks finished.
			if !state.terminated {
				out <- stream.Event{Type: stream.EventError, Err: stream.ErrStreamIncomplete.Error()}
				return
			}
			state.flushFinal(out)
			return
		}
		if err != nil {
			out <- stream.Event{Type: stream.EventError, Err: err.Error()}
			return
		}
		// Provider tracing (--debug / VIGOLIUM_OLIUM_DEBUG): echo each raw SSE
		// chunk, including the terminating [DONE], so stream-shape issues with
		// arbitrary openai-compatible backends are diagnosable.
		if DebugEnabled() && evt.Data != "" {
			debugFprintf(os.Stderr, "[%s-sse] %s", a.Name(), evt.Data)
		}
		for _, piece := range evt.JSONPayloads() {
			if piece == "[DONE]" {
				state.flushFinal(out)
				return
			}
			var parsed map[string]any
			if err := json.Unmarshal([]byte(piece), &parsed); err != nil {
				continue
			}
			// Gateways that fail after the 200 is on the wire (Ollama, Open
			// WebUI, LiteLLM, vLLM) report it as an SSE frame carrying
			// `error` and then close the stream. Ignoring it turned a model
			// crash or a context overflow into an empty text-only turn that
			// the engine nudged and then reported as the model giving up.
			if msg, ok := inStreamError(parsed, []byte(piece)); ok {
				out <- stream.Event{Type: stream.EventError, Err: fmt.Sprintf("%s: upstream error in stream: %s", a.Name(), msg)}
				return
			}
			state.handle(parsed, out)
		}
	}
}

// consumeJSON handles a 200 whose body is one JSON document instead of an
// event stream: a proxy or Open WebUI pipe that ignores stream:true, or a
// gateway reporting an error with status 200. Read as SSE it produced no
// events and ended as "stream incomplete", retried five times, with the
// real body never shown.
func (a *OpenAI) consumeJSON(body io.ReadCloser, out chan<- stream.Event) {
	defer func() { _ = body.Close() }()
	defer close(out)
	parsed, raw, err := readJSONCompletion(body)
	if err != nil {
		out <- stream.Event{Type: stream.EventError, Err: fmt.Sprintf("%s: %v", a.Name(), err)}
		return
	}
	if DebugEnabled() {
		debugFprintf(os.Stderr, "[%s-json] %s", a.Name(), raw)
	}
	if msg, ok := inStreamError(parsed, raw); ok {
		out <- stream.Event{Type: stream.EventError, Err: fmt.Sprintf("%s: upstream error: %s", a.Name(), msg)}
		return
	}
	state := &openaiState{}
	state.handle(parsed, out)
	state.flushFinal(out)
}

// inStreamError reports whether a decoded frame (or 200 JSON body) is an
// upstream failure rather than a chunk - it carries `error` and no `choices` -
// and returns its message, decoded like any other provider error body.
func inStreamError(frame map[string]any, raw []byte) (string, bool) {
	if e, ok := frame["error"]; !ok || e == nil {
		return "", false
	}
	if _, hasChoices := frame["choices"]; hasChoices {
		return "", false
	}
	return providerErrorMessage(raw), true
}

type openaiToolBuf struct {
	index     int
	id        string
	name      string
	arguments strings.Builder
	emitted   bool // true once we've sent EventToolCallStart
	// fallbackID stands in for id when the server sent none; see
	// fallbackCallID. Kept apart from id so resolveToolBuf's id matching
	// still treats the call as id-less.
	fallbackID string
}

// callID is the id to report for this call: the server's, or the fallback
// assigned when the call started.
func (b *openaiToolBuf) callID() string {
	if b.id != "" {
		return b.id
	}
	return b.fallbackID
}

type openaiState struct {
	textOpen bool
	// calls holds every tool-call accumulator in arrival order, which is
	// also the order flushFinal commits them in (an index-less stream has no
	// usable index order). Each carries the `index` it was opened with.
	calls      []*openaiToolBuf
	stopReason stream.StopReason
	usage      stream.Usage
	finalSent  bool
	// terminated records that the stream reached a real end - `[DONE]` or a
	// finish_reason - as opposed to the connection simply closing.
	terminated bool
	// sawDelta records that the stream used `delta` chunks, so a trailing
	// `message` echo of the same content is ignored.
	sawDelta bool
}

func (s *openaiState) handle(ev map[string]any, out chan<- stream.Event) {
	choices, _ := ev["choices"].([]any)
	if u, ok := ev["usage"].(map[string]any); ok {
		s.usage.Input = intField(u, "prompt_tokens")
		s.usage.Output = intField(u, "completion_tokens")
		// Cached prompt tokens live under prompt_tokens_details.cached_tokens.
		if d, ok := u["prompt_tokens_details"].(map[string]any); ok {
			s.usage.CacheRead = intField(d, "cached_tokens")
		}
	}

	for _, c := range choices {
		choice, _ := c.(map[string]any)
		if choice == nil {
			continue
		}
		delta, ok := choice["delta"].(map[string]any)
		if ok {
			s.sawDelta = true
		} else if !s.sawDelta {
			// A non-streamed `message` (a final chunk some servers send in
			// place of deltas, or a whole non-SSE completion). Only when no
			// delta arrived, or the text would be committed twice.
			delta, ok = choice["message"].(map[string]any)
		}
		if ok {
			normalizeOpenAIDelta(delta)
			s.applyDelta(delta, out)
		}
		if fr, ok := choice["finish_reason"].(string); ok && fr != "" {
			s.setStop(fr)
		}
	}
}

// resolveToolBuf picks the accumulator a tool_calls delta belongs to.
// `index` is the documented key, but some OpenAI-compatible gateways omit it
// - every call then reads as index 0, so parallel calls would merge into one
// bucket with the last name and both argument strings concatenated. An id,
// or a different function name arriving after this call's arguments have
// started, therefore opens a new call instead of overwriting the old one.
func (s *openaiState) resolveToolBuf(id, name string, idx int) *openaiToolBuf {
	if id != "" {
		for _, b := range s.calls {
			if b.id == id {
				return b
			}
		}
	}
	// Newest call at this index wins; later id-less deltas follow it.
	for i := len(s.calls) - 1; i >= 0; i-- {
		buf := s.calls[i]
		if buf.index != idx {
			continue
		}
		if id != "" && buf.id != "" {
			break // a different call, already ruled out by the id scan above
		}
		// A name change once arguments have started means a second call. A
		// name change before them may just be a name delivered in chunks.
		if name != "" && buf.name != "" && name != buf.name && buf.arguments.Len() > 0 {
			break
		}
		return buf
	}
	buf := &openaiToolBuf{index: idx}
	s.calls = append(s.calls, buf)
	return buf
}

func (s *openaiState) applyDelta(delta map[string]any, out chan<- stream.Event) {
	// Reasoning models behind openai-compatible servers stream their chain of
	// thought outside `content`: vLLM, SGLang and DeepSeek use
	// `reasoning_content`, Ollama and OpenRouter use `reasoning`. Dropping it
	// left a long silent gap in the UI and hid a model stuck looping in its
	// reasoning from the engine's repetition guard. It is never sent back.
	for _, key := range []string{"reasoning_content", "reasoning"} {
		if r, ok := delta[key].(string); ok && r != "" {
			out <- stream.Event{Type: stream.EventThinkingDelta, Delta: r}
			break
		}
	}
	if content, ok := delta["content"].(string); ok && content != "" {
		if !s.textOpen {
			out <- stream.Event{Type: stream.EventTextStart}
			s.textOpen = true
		}
		out <- stream.Event{Type: stream.EventTextDelta, Delta: content}
	}

	tcs, _ := delta["tool_calls"].([]any)
	for _, raw := range tcs {
		tc, _ := raw.(map[string]any)
		if tc == nil {
			continue
		}
		id, _ := tc["id"].(string)
		fn, _ := tc["function"].(map[string]any)
		name, _ := fn["name"].(string)
		args, _ := fn["arguments"].(string)

		buf := s.resolveToolBuf(id, name, intField(tc, "index"))
		if id != "" {
			buf.id = id
		}
		if name != "" {
			buf.name = name
		}
		if args != "" {
			buf.arguments.WriteString(args)
			if buf.emitted {
				out <- stream.Event{Type: stream.EventToolCallDelta, Delta: args}
			}
		}
		// Emit start once we have at least the function name.
		if !buf.emitted && buf.name != "" {
			if buf.id == "" {
				buf.fallbackID = fallbackCallID()
			}
			out <- stream.Event{
				Type:     stream.EventToolCallStart,
				ToolCall: &stream.ToolCall{ID: buf.callID(), Name: buf.name},
			}
			buf.emitted = true
			// Backfill any arguments that arrived alongside the name in the
			// same delta — emit them now so the consumer's running buffer
			// stays in sync with the final accumulated string.
			if buf.arguments.Len() > 0 {
				out <- stream.Event{Type: stream.EventToolCallDelta, Delta: buf.arguments.String()}
			}
		}
	}
}

func (s *openaiState) setStop(reason string) {
	s.terminated = true
	switch reason {
	case "stop":
		s.stopReason = stream.StopReasonStop
	case "length":
		s.stopReason = stream.StopReasonLength
	case "tool_calls", "function_call":
		s.stopReason = stream.StopReasonToolUse
	default:
		s.stopReason = stream.StopReasonStop
	}
}

// flushFinal emits the closing events: text_end (if a text block was open),
// one tool_call_end per buffered tool call (with arguments parsed from the
// accumulated JSON string), and a single done event with the usage tally.
// Idempotent — safe to call from both the [DONE] sentinel and the EOF path.
func (s *openaiState) flushFinal(out chan<- stream.Event) {
	if s.finalSent {
		return
	}
	s.finalSent = true

	if s.textOpen {
		out <- stream.Event{Type: stream.EventTextEnd}
		s.textOpen = false
	}
	// Commit in arrival order so multi-tool turns are deterministic.
	for _, buf := range s.calls {
		if !buf.emitted {
			continue
		}
		args, argsErr := toolArgs("openai", buf.arguments.String())
		out <- stream.Event{
			Type: stream.EventToolCallEnd,
			ToolCall: &stream.ToolCall{
				ID:        buf.callID(),
				Name:      buf.name,
				Arguments: args,
				ArgsError: argsErr,
			},
		}
	}
	usage := s.usage
	usage.TotalTokens = usage.Input + usage.Output
	out <- stream.Event{Type: stream.EventDone, StopReason: s.stopReason, Usage: &usage}
}
