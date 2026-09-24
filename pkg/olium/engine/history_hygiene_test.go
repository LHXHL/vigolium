package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/stream"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

func doneEvent() stream.Event {
	return stream.Event{Type: stream.EventDone, StopReason: stream.StopReasonStop, Usage: &stream.Usage{}}
}

// A tool call whose arguments did not parse must not run with {}: the model
// gets the parse error, naming what it sent, as the tool result.
func TestEngine_ToolWithUnparseableArgsIsNotRun(t *testing.T) {
	ft := &fakeTool{name: "read_file", out: "file contents"}
	reg := tool.NewRegistry()
	reg.Register(ft)
	prov := &scriptedProvider{fn: func(n int32) []stream.Event {
		if n > 1 {
			return []stream.Event{doneEvent()}
		}
		return []stream.Event{
			{Type: stream.EventToolCallStart, ToolCall: &stream.ToolCall{ID: "c1", Name: "read_file"}},
			{Type: stream.EventToolCallEnd, ToolCall: &stream.ToolCall{ID: "c1", Name: "read_file", Arguments: map[string]any{},
				ArgsError: `arguments are not a valid JSON object (unexpected end of JSON input): {"path":"/etc/pa`}},
			{Type: stream.EventDone, StopReason: stream.StopReasonLength, Usage: &stream.Usage{}},
		}
	}}
	eng := New(Config{Provider: prov, Tools: reg, Model: "m", MaxTurns: 3})
	got := drainEngine(t, eng.Run(context.Background(), "go"), 5*time.Second)
	if got.errMsg != "" {
		t.Fatalf("engine error: %s", got.errMsg)
	}
	if ft.called {
		t.Fatal("tool ran with arguments that did not parse")
	}
	var result *provider.Message
	for i, m := range eng.History() {
		if m.Role == provider.RoleTool && m.ToolCallID == "c1" {
			result = &eng.History()[i]
		}
	}
	if result == nil || !result.IsError {
		t.Fatalf("want an error tool result for c1, history = %+v", eng.History())
	}
	for _, want := range []string{"was not run", `{"path":"/etc/pa`, "output token limit"} {
		if !strings.Contains(result.Content, want) {
			t.Errorf("tool result %q does not mention %q", result.Content, want)
		}
	}
}

// The start fired on a placeholder name; the end carries the real one. The
// call used to be dropped (no id to match, names differ) or run under the
// placeholder name.
func TestEngine_ToolCallEndNameWins(t *testing.T) {
	ft := &fakeTool{name: "read_file", out: "ok"}
	reg := tool.NewRegistry()
	reg.Register(ft)
	prov := &scriptedProvider{fn: func(n int32) []stream.Event {
		if n > 1 {
			return []stream.Event{doneEvent()}
		}
		return []stream.Event{
			{Type: stream.EventToolCallStart, ToolCall: &stream.ToolCall{Name: "read_"}},
			{Type: stream.EventToolCallEnd, ToolCall: &stream.ToolCall{Name: "read_file", Arguments: map[string]any{"path": "/x"}}},
			doneEvent(),
		}
	}}
	eng := New(Config{Provider: prov, Tools: reg, Model: "m", MaxTurns: 3})
	got := drainEngine(t, eng.Run(context.Background(), "go"), 5*time.Second)
	if got.errMsg != "" {
		t.Fatalf("engine error: %s", got.errMsg)
	}
	if !ft.called {
		t.Fatalf("read_file never ran; history = %+v", eng.History())
	}
}

func TestMatchInflight_SingleCallFallback(t *testing.T) {
	one := []*provider.ToolCall{{Name: "read_"}}
	if got := matchInflight(one, &stream.ToolCall{Name: "read_file"}); got != 0 {
		t.Fatalf("single in-flight call with a renamed end: got %d, want 0", got)
	}
	// Conflicting ids are a stray end, never a match.
	withID := []*provider.ToolCall{{ID: "a", Name: "x"}}
	if got := matchInflight(withID, &stream.ToolCall{ID: "b", Name: "y"}); got != -1 {
		t.Fatalf("conflicting ids matched: %d", got)
	}
	// Two in flight with no way to tell them apart: do not guess.
	two := []*provider.ToolCall{{Name: "a"}, {Name: "b"}}
	if got := matchInflight(two, &stream.ToolCall{Name: "c"}); got != -1 {
		t.Fatalf("ambiguous end matched: %d", got)
	}
}

// A Run that fails before the model answers leaves its user message
// unanswered; the next Run must not add a second user message in a row,
// which alternation-enforcing chat templates reject.
func TestEngine_NoConsecutiveUserMessagesAfterFailedRun(t *testing.T) {
	prov := &scriptedProvider{fn: func(n int32) []stream.Event {
		if n == 1 {
			return []stream.Event{{Type: stream.EventError, Err: "400 bad request"}}
		}
		return []stream.Event{
			{Type: stream.EventTextDelta, Delta: "answer"},
			doneEvent(),
		}
	}}
	eng := New(Config{Provider: prov, Tools: tool.NewRegistry(), Model: "m", MaxTurns: 2})
	first := drainEngine(t, eng.Run(context.Background(), "first prompt"), 5*time.Second)
	if first.errMsg == "" {
		t.Fatal("first run should fail")
	}
	_ = drainEngine(t, eng.Run(context.Background(), "second prompt"), 5*time.Second)

	sent := prov.lastRequest().Messages
	for i := 1; i < len(sent); i++ {
		if sent[i].Role == provider.RoleUser && sent[i-1].Role == provider.RoleUser {
			t.Fatalf("consecutive user messages sent: %+v", sent)
		}
	}
	if len(sent) == 0 || !strings.Contains(sent[0].Text, "first prompt") || !strings.Contains(sent[0].Text, "second prompt") {
		t.Fatalf("both prompts should survive in one user turn: %+v", sent)
	}
}

// An assistant turn with no text and no tool calls is committed with a
// placeholder, never as an empty message.
func TestEngine_EmptyAssistantTurnGetsPlaceholder(t *testing.T) {
	prov := &scriptedProvider{fn: func(int32) []stream.Event {
		return []stream.Event{
			{Type: stream.EventThinkingDelta, Delta: "thinking only"},
			doneEvent(),
		}
	}}
	eng := New(Config{Provider: prov, Tools: tool.NewRegistry(), Model: "m", MaxTurns: 2})
	_ = drainEngine(t, eng.Run(context.Background(), "go"), 5*time.Second)
	for _, m := range eng.History() {
		if m.Role == provider.RoleAssistant && m.Text == "" && len(m.ToolCalls) == 0 {
			t.Fatalf("empty assistant message committed: %+v", eng.History())
		}
	}
}

func TestAppendUserTurn(t *testing.T) {
	h := appendUserTurn(nil, "a")
	h = append(h, provider.Message{Role: provider.RoleAssistant, Text: "r"})
	h = appendUserTurn(h, "b")
	if len(h) != 3 {
		t.Fatalf("user after assistant must be a new message: %+v", h)
	}
	h = appendUserTurn(h, "c")
	if len(h) != 3 || h[2].Text != "b\n\nc" {
		t.Fatalf("user after user must merge: %+v", h)
	}
}
