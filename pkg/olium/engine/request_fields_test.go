package engine

import (
	"context"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// ReasoningEffort, SessionID and MaxTokens were configurable, validated and
// displayed long before anything put them on a request — the effort dial in
// particular reached the TUI banner and the session transcript while every
// call still ran at the provider's default. Nothing errors when they are
// dropped, so assert they leave the engine.
func TestEngineForwardsRequestTuning(t *testing.T) {
	prov := &scriptedProvider{fn: func(int32) []stream.Event {
		return []stream.Event{
			{Type: stream.EventTextDelta, Delta: "done"},
			{Type: stream.EventDone, StopReason: stream.StopReasonStop},
		}
	}}
	eng := New(Config{
		Provider:        prov,
		Model:           "claude-opus-5",
		System:          "sys",
		MaxTurns:        1,
		ReasoningEffort: "xhigh",
		SessionID:       "run-abc",
		MaxTokens:       32000,
	})
	drainEngine(t, eng.Run(context.Background(), "go"), 5*time.Second)

	got := prov.lastRequest()
	if got.ReasoningEff != "xhigh" {
		t.Errorf("ReasoningEff = %q, want %q", got.ReasoningEff, "xhigh")
	}
	if got.SessionID != "run-abc" {
		t.Errorf("SessionID = %q, want %q", got.SessionID, "run-abc")
	}
	if got.MaxTokens != 32000 {
		t.Errorf("MaxTokens = %d, want 32000", got.MaxTokens)
	}
}

// SessionCacheKey exists because filepath.Base("") is ".", which every
// keyless run would otherwise share as a prompt-cache namespace.
func TestSessionCacheKey(t *testing.T) {
	if got := SessionCacheKey(""); got != "" {
		t.Errorf("SessionCacheKey(\"\") = %q, want empty", got)
	}
	if got := SessionCacheKey("   "); got != "" {
		t.Errorf("SessionCacheKey(whitespace) = %q, want empty", got)
	}
	if got := SessionCacheKey("/tmp/runs/abc-123"); got != "abc-123" {
		t.Errorf("SessionCacheKey = %q, want abc-123", got)
	}
}
