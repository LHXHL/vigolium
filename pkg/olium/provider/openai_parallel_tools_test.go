package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// sseStream serves body as an SSE response and returns every event the
// openai-compatible driver produces from it.
func sseStream(t *testing.T, body string) []stream.Event {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	events, err := NewOpenAICompatible(srv.URL+"/v1", "k", nil, nil).Stream(
		context.Background(),
		Request{Model: "test-model", Messages: []Message{{Role: RoleUser, Text: "go"}}},
	)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	var out []stream.Event
	for ev := range events {
		out = append(out, ev)
	}
	return out
}

// toolCallsOf splits the stream's tool-call lifecycle events.
func toolCallsOf(events []stream.Event) (starts, ends []stream.ToolCall) {
	for _, ev := range events {
		switch ev.Type {
		case stream.EventToolCallStart:
			starts = append(starts, *ev.ToolCall)
		case stream.EventToolCallEnd:
			ends = append(ends, *ev.ToolCall)
		}
	}
	return starts, ends
}

// errorOf returns the stream's error text, or "" if it ended cleanly.
func errorOf(events []stream.Event) string {
	for _, ev := range events {
		if ev.Type == stream.EventError {
			return ev.Err
		}
	}
	return ""
}

// TestOpenAI_ParallelToolCalls_StartEndPairing pins the wire shape a
// chat-completions endpoint uses for parallel tool calls: both calls stream
// interleaved by index, and every tool_call_end is flushed at the close of
// the stream. Each end must carry its own id, name and arguments - a
// consumer that pairs ends to starts by id depends on it (see
// engine.streamOnce, where a single "current call" pointer used to hand call
// B's name call A's arguments and drop one call entirely).
func TestOpenAI_ParallelToolCalls_StartEndPairing(t *testing.T) {
	events := sseStream(t, `data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_a","function":{"name":"query_findings","arguments":"{\"sea"}}]}}]}

data: {"choices":[{"delta":{"tool_calls":[{"index":1,"id":"call_b","function":{"name":"web_fetch","arguments":"{\"url\""}}]}}]}

data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"rch\":\"x\"}"}}]}}]}

data: {"choices":[{"delta":{"tool_calls":[{"index":1,"function":{"arguments":":\"https://example.test/\"}"}}]}}]}

data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}

data: [DONE]

`)
	if err := errorOf(events); err != "" {
		t.Fatalf("stream error: %s", err)
	}
	starts, ends := toolCallsOf(events)
	if len(starts) != 2 || len(ends) != 2 {
		t.Fatalf("got %d starts / %d ends, want 2 / 2 (starts=%+v ends=%+v)", len(starts), len(ends), starts, ends)
	}
	for _, e := range ends {
		switch e.ID {
		case "call_a":
			if e.Name != "query_findings" || e.Arguments["search"] != "x" {
				t.Errorf("call_a = %+v, want query_findings with search=x", e)
			}
		case "call_b":
			if e.Name != "web_fetch" || e.Arguments["url"] != "https://example.test/" {
				t.Errorf("call_b = %+v, want web_fetch with its own url", e)
			}
		default:
			t.Errorf("unexpected tool-call id %q", e.ID)
		}
	}
}

// TestOpenAI_ParallelToolCalls_NoIndexField covers gateways that omit the
// `index` field on tool_calls deltas. Without id-based bucketing every call
// reads as index 0, so two parallel calls collapse into one with the last
// name and both argument strings concatenated (which then fails to parse,
// leaving the model with an empty-args call it can't explain).
func TestOpenAI_ParallelToolCalls_NoIndexField(t *testing.T) {
	_, ends := toolCallsOf(sseStream(t, `data: {"choices":[{"delta":{"tool_calls":[{"id":"call_a","function":{"name":"query_findings","arguments":"{\"search\":\"x\"}"}}]}}]}

data: {"choices":[{"delta":{"tool_calls":[{"id":"call_b","function":{"name":"web_fetch","arguments":"{\"url\":\"https://example.test/\"}"}}]}}]}

data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}

data: [DONE]

`))
	if len(ends) != 2 {
		t.Fatalf("got %d tool calls, want 2: %+v", len(ends), ends)
	}
	if ends[0].Name != "query_findings" || ends[0].Arguments["search"] != "x" {
		t.Errorf("first call = %+v, want query_findings with search=x", ends[0])
	}
	if ends[1].Name != "web_fetch" || ends[1].Arguments["url"] != "https://example.test/" {
		t.Errorf("second call = %+v, want web_fetch with its own url", ends[1])
	}
}

// TestOpenAI_ParallelToolCalls_NoIndexNoID is the worst-case gateway: neither
// `index` nor `id` on any delta. The only remaining signal that call B has
// started is its different function name arriving after call A's arguments.
func TestOpenAI_ParallelToolCalls_NoIndexNoID(t *testing.T) {
	_, ends := toolCallsOf(sseStream(t, `data: {"choices":[{"delta":{"tool_calls":[{"function":{"name":"query_findings","arguments":"{\"search\":\"x\"}"}}]}}]}

data: {"choices":[{"delta":{"tool_calls":[{"function":{"name":"web_fetch","arguments":"{\"url\":\"https://example.test/\"}"}}]}}]}

data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}

data: [DONE]

`))
	if len(ends) != 2 {
		t.Fatalf("got %d tool calls, want 2: %+v", len(ends), ends)
	}
	if ends[0].Arguments["search"] != "x" || ends[1].Arguments["url"] != "https://example.test/" {
		t.Errorf("arguments merged across calls: %+v", ends)
	}
}

// TestOpenAI_ChunkedFunctionNameStaysOneCall is the counter-case: a backend
// that splits the function name across deltas must NOT be read as two calls.
func TestOpenAI_ChunkedFunctionNameStaysOneCall(t *testing.T) {
	_, ends := toolCallsOf(sseStream(t, `data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"query_"}}]}}]}

data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"query_records"}}]}}]}

data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"host\":\"a\"}"}}]}}]}

data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}

data: [DONE]

`))
	if len(ends) != 1 {
		t.Fatalf("a chunked name produced %d calls, want 1: %+v", len(ends), ends)
	}
	if ends[0].Name != "query_records" || ends[0].Arguments["host"] != "a" {
		t.Errorf("call = %+v, want query_records host=a", ends[0])
	}
}

// TestOpenAI_TruncatedStreamIsAnError covers a connection cut mid-response:
// no `[DONE]`, no finish_reason. Synthesizing a terminal event on EOF made
// that indistinguishable from a finished turn, so the engine committed a
// truncated assistant message - on this provider, the one the bug was
// reported against.
func TestOpenAI_TruncatedStreamIsAnError(t *testing.T) {
	events := sseStream(t, `data: {"choices":[{"delta":{"content":"half a th"}}]}

`)
	if err := errorOf(events); err == "" {
		t.Error("a stream that ended without [DONE] or a finish_reason must surface an error")
	}
	for _, ev := range events {
		if ev.Type == stream.EventDone {
			t.Error("a truncated stream must not emit EventDone")
		}
	}
}

// TestOpenAI_NoDoneSentinelButFinishReasonIsComplete guards the
// compatibility case the check must not break: gateways that close the
// stream after a finish_reason without ever sending `[DONE]`.
func TestOpenAI_NoDoneSentinelButFinishReasonIsComplete(t *testing.T) {
	events := sseStream(t, `data: {"choices":[{"delta":{"content":"all done"},"finish_reason":"stop"}]}

`)
	if err := errorOf(events); err != "" {
		t.Errorf("a finish_reason is a real terminator; got error %q", err)
	}
	var sawDone bool
	for _, ev := range events {
		if ev.Type == stream.EventDone {
			sawDone = true
		}
	}
	if !sawDone {
		t.Error("expected EventDone after a finish_reason")
	}
}
