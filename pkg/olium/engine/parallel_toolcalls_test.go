package engine

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/stream"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// parallelToolProvider reproduces the OpenAI chat-completions streaming shape
// for a turn with two parallel tool calls: both starts are emitted as soon as
// the function names arrive, then both ends are flushed at the end of the
// stream (openaiState.flushFinal).
type parallelToolProvider struct{}

func (parallelToolProvider) Name() string { return "scripted-parallel" }

func (parallelToolProvider) Stream(_ context.Context, req provider.Request) (<-chan stream.Event, error) {
	ch := make(chan stream.Event, 16)
	toolResultSeen := false
	for _, m := range req.Messages {
		if m.Role == provider.RoleTool {
			toolResultSeen = true
		}
	}
	go func() {
		defer close(ch)
		if !toolResultSeen {
			ch <- stream.Event{Type: stream.EventToolCallStart, ToolCall: &stream.ToolCall{ID: "call_a", Name: "query_findings"}}
			ch <- stream.Event{Type: stream.EventToolCallStart, ToolCall: &stream.ToolCall{ID: "call_b", Name: "web_fetch"}}
			ch <- stream.Event{Type: stream.EventToolCallEnd, ToolCall: &stream.ToolCall{
				ID: "call_a", Name: "query_findings", Arguments: map[string]any{"search": "example.test", "limit": float64(100)},
			}}
			ch <- stream.Event{Type: stream.EventToolCallEnd, ToolCall: &stream.ToolCall{
				ID: "call_b", Name: "web_fetch", Arguments: map[string]any{"url": "https://example.test/"},
			}}
			ch <- stream.Event{Type: stream.EventDone, StopReason: stream.StopReasonToolUse, Usage: &stream.Usage{}}
			return
		}
		ch <- stream.Event{Type: stream.EventTextDelta, Delta: "done"}
		ch <- stream.Event{Type: stream.EventDone, StopReason: stream.StopReasonStop, Usage: &stream.Usage{}}
	}()
	return ch, nil
}

func TestEngine_ParallelToolCallsNotCrossWired(t *testing.T) {
	reg := tool.NewRegistry()
	reg.Register(&fakeTool{name: "query_findings", out: "ok"})
	reg.Register(&fakeTool{name: "web_fetch", out: "ok"})

	eng := New(Config{Provider: parallelToolProvider{}, Tools: reg, MaxTurns: 2})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var calls []stream.ToolCall
	for ev := range eng.Run(ctx, "go") {
		if ev.Type == EventTurnDone && len(ev.ToolCalls) > 0 {
			calls = append(calls, ev.ToolCalls...)
		}
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 tool calls, got %d: %+v", len(calls), calls)
	}
	for _, c := range calls {
		switch c.Name {
		case "query_findings":
			if c.Arguments["search"] == nil {
				t.Errorf("query_findings lost its args: %+v", c.Arguments)
			}
		case "web_fetch":
			if c.Arguments["url"] == nil {
				t.Errorf("web_fetch got the wrong args: %+v", c.Arguments)
			}
		default:
			t.Errorf("unexpected tool name %q", c.Name)
		}
	}
}

// slowTool declares a longer budget than the engine default via
// tool.LongRunning.
type slowTool struct{ *fakeTool }

func (slowTool) MaxDuration() time.Duration { return 42 * time.Minute }

func TestEngine_TimeoutForHonorsLongRunning(t *testing.T) {
	eng := New(Config{Provider: parallelToolProvider{}, ToolTimeout: time.Minute})
	if got := eng.timeoutFor(&fakeTool{name: "plain"}); got != time.Minute {
		t.Errorf("plain tool timeout = %s, want the engine default 1m", got)
	}
	if got := eng.timeoutFor(slowTool{&fakeTool{name: "scan"}}); got != 42*time.Minute {
		t.Errorf("long-running tool timeout = %s, want its declared 42m", got)
	}
}

// failingTool stands in for a tool whose schema names a required argument;
// only Schema() is exercised, since the test drives noteToolOutcome directly.
type failingTool struct{ *fakeTool }

func (failingTool) Schema() map[string]any {
	return map[string]any{"type": "object", "required": []string{"url"}}
}

// TestEngine_RepeatedIdenticalFailureEscalates covers the loop breaker: the
// first failure reads as it always did, and a verbatim repeat gets told so,
// with the tool's required arguments named.
func TestEngine_RepeatedIdenticalFailureEscalates(t *testing.T) {
	ft := failingTool{&fakeTool{name: "web_fetch"}}
	eng := New(Config{Provider: parallelToolProvider{}})
	tc := provider.ToolCall{ID: "c1", Name: "web_fetch", Args: map[string]any{"search": "x"}}
	fail := func() tool.Result { return tool.Result{Content: "error: url is required", IsError: true} }

	first := eng.noteToolOutcome(ft, tc, fail())
	if strings.Contains(first.Content, "attempt") {
		t.Errorf("first failure should not be escalated: %q", first.Content)
	}

	second := eng.noteToolOutcome(ft, tc, fail())
	if !strings.Contains(second.Content, "attempt 2") {
		t.Errorf("repeat not escalated: %q", second.Content)
	}
	if !strings.Contains(second.Content, "requires: url") {
		t.Errorf("escalation should name the required args: %q", second.Content)
	}
	if !strings.Contains(second.Content, "url is required") {
		t.Errorf("original error text must survive: %q", second.Content)
	}

	// Different arguments are a different call - not a repeat.
	other := provider.ToolCall{ID: "c2", Name: "web_fetch", Args: map[string]any{"search": "y"}}
	if got := eng.noteToolOutcome(ft, other, fail()); strings.Contains(got.Content, "attempt") {
		t.Errorf("distinct arguments must not count as a repeat: %q", got.Content)
	}

	// A success clears the streak.
	eng.noteToolOutcome(ft, tc, tool.Result{Content: "ok"})
	if got := eng.noteToolOutcome(ft, tc, fail()); strings.Contains(got.Content, "attempt") {
		t.Errorf("streak should reset after a success: %q", got.Content)
	}
}

// blockingTool waits for the context, simulating a tool still running when
// the run is cancelled.
type blockingTool struct{ *fakeTool }

func (blockingTool) IsReadOnly() bool { return false } // force the serial path

func (blockingTool) Execute(ctx context.Context, _ map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	<-ctx.Done()
	return tool.Result{Content: "cancelled"}, nil
}

// TestEngine_CancelLeavesNoUnansweredToolCall pins the history invariant every
// provider enforces: an assistant turn with N tool calls must be followed by N
// tool results. Cancelling mid-batch used to return with the tail unanswered,
// which is a hard 400 the next time that history is sent (a retry, a TUI
// follow-up, a Fork, a post-halt re-entry).
func TestEngine_CancelLeavesNoUnansweredToolCall(t *testing.T) {
	reg := tool.NewRegistry()
	reg.Register(blockingTool{&fakeTool{name: "query_findings"}})
	reg.Register(blockingTool{&fakeTool{name: "web_fetch"}})

	eng := New(Config{Provider: parallelToolProvider{}, Tools: reg, MaxTurns: 2})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	for range eng.Run(ctx, "go") { //nolint:revive // draining
	}

	var pendingIDs []string
	answered := map[string]int{}
	for _, m := range eng.History() {
		switch m.Role {
		case provider.RoleAssistant:
			for _, tc := range m.ToolCalls {
				pendingIDs = append(pendingIDs, tc.ID)
			}
		case provider.RoleTool:
			answered[m.ToolCallID]++
		}
	}
	if len(pendingIDs) != 2 {
		t.Fatalf("expected the provider's 2 tool calls in history, got %d", len(pendingIDs))
	}
	for _, id := range pendingIDs {
		if n := answered[id]; n != 1 {
			t.Errorf("tool call %q has %d tool results, want exactly 1 - anything else is a provider 400", id, n)
		}
	}
}

// truncatedStreamProvider closes its channel without ever emitting
// EventDone, the shape of a connection cut mid-SSE.
type truncatedStreamProvider struct{ attempts atomic.Int32 }

func (p *truncatedStreamProvider) Name() string { return "truncated" }

func (p *truncatedStreamProvider) Stream(context.Context, provider.Request) (<-chan stream.Event, error) {
	p.attempts.Add(1)
	ch := make(chan stream.Event, 4)
	go func() {
		defer close(ch)
		ch <- stream.Event{Type: stream.EventTextDelta, Delta: "half a th"}
	}()
	return ch, nil
}

// TestEngine_TruncatedStreamIsNotASuccessfulTurn covers the silent early
// exit: a stream that dies mid-flight used to return err == nil, so the
// engine committed a truncated assistant message and carried on as if the
// model had finished speaking.
func TestEngine_TruncatedStreamIsNotASuccessfulTurn(t *testing.T) {
	prov := &truncatedStreamProvider{}
	eng := New(Config{
		Provider: prov, Tools: tool.NewRegistry(), MaxTurns: 2,
		RetryInitialBackoff: time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var sawErr bool
	for ev := range eng.Run(ctx, "go") {
		if ev.Type == EventError {
			sawErr = true
		}
	}
	if !sawErr {
		t.Error("a stream that ended without its terminal event must surface an error, not a completed turn")
	}
	if n := prov.attempts.Load(); int(n) != maxStreamAttempts {
		t.Errorf("expected the incomplete stream to be retried %d times, got %d", maxStreamAttempts, n)
	}
	for _, m := range eng.History() {
		if m.Role == provider.RoleAssistant {
			t.Errorf("a truncated turn must not be committed to history: %+v", m)
		}
	}
}
