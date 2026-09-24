package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// Regressions for response shapes openai-compatible servers send instead of
// the canonical streaming format. Each one used to be dropped silently.

// serveBody answers every request with body and the given content type.
func serveBody(t *testing.T, contentType, body string) []stream.Event {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	ch, err := NewOpenAICompatible(srv.URL+"/v1", "", nil, nil).Stream(context.Background(),
		Request{Model: "m", Messages: []Message{{Role: RoleUser, Text: "go"}}})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	var out []stream.Event
	for ev := range ch {
		out = append(out, ev)
	}
	return out
}

func textOf(events []stream.Event) string {
	var b strings.Builder
	for _, ev := range events {
		if ev.Type == stream.EventTextDelta {
			b.WriteString(ev.Delta)
		}
	}
	return b.String()
}

func lastType(events []stream.Event) stream.EventType {
	if len(events) == 0 {
		return ""
	}
	return events[len(events)-1].Type
}

// A proxy that ignores stream:true answers with one JSON completion. Read as
// SSE it produced nothing and failed as "stream incomplete" after 5 retries.
func TestOpenAI_NonStreamedJSONCompletion(t *testing.T) {
	events := serveBody(t, "application/json", `{
  "choices": [{
    "message": {
      "role": "assistant",
      "content": "checking",
      "tool_calls": [
        {"id": "c1", "type": "function", "function": {"name": "list_records", "arguments": "{\"limit\":5}"}},
        {"id": "c2", "type": "function", "function": {"name": "halt_scan", "arguments": "{}"}}
      ]
    },
    "finish_reason": "tool_calls"
  }],
  "usage": {"prompt_tokens": 10, "completion_tokens": 3}
}`)
	if lastType(events) != stream.EventDone {
		t.Fatalf("want a clean done, got %+v", events)
	}
	if got := textOf(events); got != "checking" {
		t.Fatalf("text = %q", got)
	}
	_, ends := toolCallsOf(events)
	if len(ends) != 2 || ends[0].Name != "list_records" || ends[0].Arguments["limit"] != float64(5) || ends[1].Name != "halt_scan" {
		t.Fatalf("tool calls = %+v", ends)
	}
}

func TestOpenAI_JSONErrorBodyWith200(t *testing.T) {
	events := serveBody(t, "application/json", `{"error":{"message":"model not loaded"}}`)
	if lastType(events) != stream.EventError || !strings.Contains(events[len(events)-1].Err, "model not loaded") {
		t.Fatalf("want the upstream error, got %+v", events)
	}
}

// Events separated by single newlines are folded into one SSE event whose
// data is several JSON documents joined by "\n".
func TestOpenAI_SingleNewlineSeparatedEvents(t *testing.T) {
	events := serveBody(t, "text/event-stream",
		"data: {\"choices\":[{\"delta\":{\"content\":\"hel\"}}]}\n"+
			"data: {\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}]}\n"+
			"data: [DONE]\n")
	if got := textOf(events); got != "hello" {
		t.Fatalf("text = %q (events %+v)", got, events)
	}
	if lastType(events) != stream.EventDone {
		t.Fatalf("want done, got %+v", events)
	}
}

func TestOpenAI_ContentAsArrayOfParts(t *testing.T) {
	events := sseStream(t, `data: {"choices":[{"delta":{"content":[{"type":"text","text":"part one, "},{"type":"text","text":"part two"}]}}]}

data: {"choices":[{"delta":{},"finish_reason":"stop"}]}

data: [DONE]

`)
	if got := textOf(events); got != "part one, part two" {
		t.Fatalf("text = %q", got)
	}
}

// A final chunk carrying `message` instead of deltas is used when nothing
// streamed, and ignored when it only echoes what the deltas already said.
func TestOpenAI_MessageChunk(t *testing.T) {
	onlyMessage := sseStream(t, `data: {"choices":[{"message":{"role":"assistant","content":"whole answer"},"finish_reason":"stop"}]}

data: [DONE]

`)
	if got := textOf(onlyMessage); got != "whole answer" {
		t.Fatalf("message-only text = %q", got)
	}
	echo := sseStream(t, `data: {"choices":[{"delta":{"content":"streamed"}}]}

data: {"choices":[{"message":{"role":"assistant","content":"streamed"},"finish_reason":"stop"}]}

data: [DONE]

`)
	if got := textOf(echo); got != "streamed" {
		t.Fatalf("echoed message duplicated the text: %q", got)
	}
}

func TestOpenAI_ToolArgumentShapes(t *testing.T) {
	cases := []struct {
		name      string
		arguments string // raw JSON value of function.arguments
		wantPath  string
		wantErr   bool
	}{
		{"canonical string", `"{\"path\":\"/a\"}"`, "/a", false},
		{"object instead of string", `{"path":"/b"}`, "/b", false},
		{"double-encoded", `"\"{\\\"path\\\":\\\"/c\\\"}\""`, "/c", false},
		{"truncated", `"{\"path\":\"/etc/pa"`, "", true},
		{"two objects concatenated", `"{\"path\":1}{\"path\":2}"`, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := sseStream(t, `data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"read_file","arguments":`+tc.arguments+`}}]}}]}

data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}

data: [DONE]

`)
			_, ends := toolCallsOf(events)
			if len(ends) != 1 {
				t.Fatalf("want 1 call, got %+v", events)
			}
			end := ends[0]
			if tc.wantErr {
				if end.ArgsError == "" || len(end.Arguments) != 0 {
					t.Fatalf("want ArgsError and empty args, got %+v", end)
				}
				return
			}
			if end.ArgsError != "" || end.Arguments["path"] != tc.wantPath {
				t.Fatalf("want path %q, got %+v", tc.wantPath, end)
			}
		})
	}
}

// The configured URL 404s and the /v1-toggled alternate answers with an
// error. The alternate exists, so it must be the one remembered: pinning the
// dead spelling made every later request 404 with no fallback.
func TestOpenAICompatible_AltAnswersWithErrorIsSettled(t *testing.T) {
	var altCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			http.NotFound(w, r)
			return
		}
		if altCalls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":{"message":"slow down"}}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	}))
	defer srv.Close()

	p := NewOpenAICompatible(srv.URL, "", nil, nil) // resolves to /v1/chat/completions
	req := Request{Model: "m", Messages: []Message{{Role: RoleUser, Text: "go"}}}
	if _, err := p.Stream(context.Background(), req); err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("first call: want the alternate's 429, got %v", err)
	}
	ch, err := p.Stream(context.Background(), req)
	if err != nil {
		t.Fatalf("second call should reach the settled alternate, got %v", err)
	}
	var events []stream.Event
	for ev := range ch {
		events = append(events, ev)
	}
	if textOf(events) != "ok" {
		t.Fatalf("second call events = %+v", events)
	}
}

// Open WebUI's catch-all static mount answers a POST to an unknown path with
// 405, not 404; that must trigger the alternate spelling too.
func TestOpenAICompatible_405TriggersAlternate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	}))
	defer srv.Close()
	ch, err := NewOpenAICompatible(srv.URL, "", nil, nil).Stream(context.Background(),
		Request{Model: "m", Messages: []Message{{Role: RoleUser, Text: "go"}}})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	var events []stream.Event
	for ev := range ch {
		events = append(events, ev)
	}
	if textOf(events) != "ok" {
		t.Fatalf("events = %+v", events)
	}
}

// A strict validator rejects stream_options; the driver retries without it
// and stops sending it to that server.
func TestOpenAICompatible_StreamOptionsRejectedIsDropped(t *testing.T) {
	var mu sync.Mutex
	var sawOptions []bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, has := body["stream_options"]
		mu.Lock()
		sawOptions = append(sawOptions, has)
		mu.Unlock()
		if has {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = io.WriteString(w, `{"detail":[{"loc":["body","stream_options"],"msg":"Extra inputs are not permitted","type":"extra_forbidden"}]}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	}))
	defer srv.Close()

	p := NewOpenAICompatible(srv.URL+"/v1", "", nil, nil)
	req := Request{Model: "m", Messages: []Message{{Role: RoleUser, Text: "go"}}}
	for i := 0; i < 2; i++ {
		ch, err := p.Stream(context.Background(), req)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		var events []stream.Event
		for ev := range ch {
			events = append(events, ev)
		}
		if textOf(events) != "ok" {
			t.Fatalf("call %d events = %+v", i, events)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	// call 1: rejected + retried; call 2: sent without it from the start.
	if want := []bool{true, false, false}; len(sawOptions) != 3 || sawOptions[0] != want[0] || sawOptions[1] || sawOptions[2] {
		t.Fatalf("stream_options per request = %v, want %v", sawOptions, want)
	}
}

func TestDecodeToolArguments(t *testing.T) {
	for raw, wantErr := range map[string]bool{
		``:                  false,
		`null`:              false,
		`{}`:                false,
		`{"a":1}`:           false,
		`"{\"a\":1}"`:       false,
		`[1,2]`:             true,
		`{"a":`:             true,
		`"not json at all"`: true,
		`{"a":1}{"a":2}`:    true,
	} {
		args, argsErr := decodeToolArguments(raw)
		if (argsErr != "") != wantErr {
			t.Errorf("decodeToolArguments(%q) err = %q, wantErr %v", raw, argsErr, wantErr)
		}
		if args == nil {
			t.Errorf("decodeToolArguments(%q) returned nil args", raw)
		}
	}
}

// A server that streams tool calls without ids gets one per call, assigned
// when the call starts, so the start event, the end event and every later
// consumer (history, tool result, TUI card) carry the same unique id.
func TestOpenAI_IDLessToolCallsGetStableUniqueIDs(t *testing.T) {
	events := sseStream(t, `data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"read_file","arguments":"{\"path\":\"/a\"}"}},{"index":1,"function":{"name":"read_file","arguments":"{\"path\":\"/b\"}"}}]}}]}

data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}

data: [DONE]

`)
	starts, ends := toolCallsOf(events)
	if len(starts) != 2 || len(ends) != 2 {
		t.Fatalf("want 2 calls, got starts=%+v ends=%+v", starts, ends)
	}
	for i := range starts {
		if starts[i].ID == "" || starts[i].ID != ends[i].ID {
			t.Fatalf("call %d: start id %q, end id %q", i, starts[i].ID, ends[i].ID)
		}
	}
	if starts[0].ID == starts[1].ID {
		t.Fatalf("both calls got id %q", starts[0].ID)
	}
}
