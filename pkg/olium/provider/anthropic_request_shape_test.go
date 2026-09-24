package provider

import (
	"encoding/json"
	"strings"
	"testing"
)

// The Anthropic request used to ship with no thinking config, a hardcoded
// 8192 output ceiling, and cache breakpoints only on the fixed prefix. Each
// of those is a silent quality or cost regression rather than an error, so
// pin the emitted shape.
func TestBuildAnthropicRequestShape(t *testing.T) {
	req := Request{
		Model:        "claude-opus-5",
		System:       "you are a scanner",
		ReasoningEff: "high",
		CacheControl: true,
		Messages: []Message{
			{Role: RoleUser, Text: "audit this"},
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t1", Name: "run_native_scan"}}},
			{Role: RoleTool, ToolCallID: "t1", Content: "two findings"},
		},
		Tools: []ToolDef{{Name: "run_native_scan", Schema: map[string]any{"type": "object"}}},
	}
	body := buildAnthropicRequest(req)

	if body.Thinking == nil || body.Thinking.Type != "adaptive" {
		t.Errorf("thinking = %+v, want adaptive (omitting it runs Opus 4.7+ with reasoning off)", body.Thinking)
	}
	if body.OutputConfig == nil || body.OutputConfig.Effort != "high" {
		t.Errorf("output_config = %+v, want effort=high from Request.ReasoningEff", body.OutputConfig)
	}
	if body.MaxTokens != defaultAnthropicMaxTokens {
		t.Errorf("max_tokens = %d, want %d", body.MaxTokens, defaultAnthropicMaxTokens)
	}

	// The tail of the transcript carries a breakpoint so a long agent loop
	// reads the prefix it wrote last turn instead of re-paying for it.
	last := body.Messages[len(body.Messages)-1]
	tr, ok := last.Content[len(last.Content)-1].(anthContentToolResult)
	if !ok {
		t.Fatalf("last content block = %T, want tool_result", last.Content[len(last.Content)-1])
	}
	if tr.CacheControl == nil {
		t.Error("last tool_result has no cache_control breakpoint")
	}

	// Exactly three: system, last tool, last tool_result — inside Anthropic's
	// limit of four, and a count that moves if a breakpoint lands elsewhere.
	raw, _ := json.Marshal(body)
	if n := strings.Count(string(raw), `"cache_control"`); n != 3 {
		t.Errorf("%d cache_control breakpoints, want 3 (system, last tool, last tool_result)", n)
	}
}

func TestBuildAnthropicRequestOverrides(t *testing.T) {
	// An explicit ceiling wins over the default.
	if got := buildAnthropicRequest(Request{Model: "claude-opus-5", MaxTokens: 4096}).MaxTokens; got != 4096 {
		t.Errorf("max_tokens = %d, want the caller's 4096", got)
	}
	// A gateway fronting a non-Claude model must not be sent thinking.
	if body := buildAnthropicRequest(Request{Model: "llama-3.3-70b"}); body.Thinking != nil {
		t.Errorf("thinking = %+v on a non-Claude model, want nil", body.Thinking)
	}
	// Pre-4.6 Claude models take budget_tokens, not adaptive.
	if body := buildAnthropicRequest(Request{Model: "claude-haiku-4-5"}); body.Thinking != nil {
		t.Errorf("thinking = %+v on claude-haiku-4-5, want nil", body.Thinking)
	}
	// No caching asked for → no breakpoints anywhere.
	body := buildAnthropicRequest(Request{
		Model:    "claude-opus-5",
		System:   "s",
		Messages: []Message{{Role: RoleUser, Text: "hello"}},
	})
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), "cache_control") {
		t.Error("cache_control emitted with CacheControl=false")
	}
}

// A text tail is either turn one (whose prefix already carries its own
// breakpoints) or a single-shot caller that never issues a second request, so
// marking it would buy a cache write nobody reads back.
func TestApplyAnthropicMessageCacheSkipsTextTail(t *testing.T) {
	msgs := []anthMessage{{Role: "user", Content: []any{anthContentText{Type: "text", Text: strings.Repeat("x", 8192)}}}}
	applyAnthropicMessageCache(msgs, Request{CacheControl: true})
	if got := msgs[0].Content[0].(anthContentText); got.CacheControl != nil {
		t.Error("marked a text tail; only a tool_result tail is re-read by a later turn")
	}
}

// A deny-list let 4.0-era ids (and anything unrecognised) through to a 400.
func TestSupportsAdaptiveThinking(t *testing.T) {
	yes := []string{"claude-opus-5", "claude-opus-5-5", "claude-opus-4-6", "claude-opus-4-8", "claude-sonnet-5", "claude-fable-5-1", "CLAUDE-OPUS-5"}
	no := []string{"claude-opus-4-20250514", "claude-sonnet-4-20250514", "claude-haiku-4-5", "claude-opus-4-5", "claude-3-7-sonnet", "llama-3.3-70b", "my-proxy/claude-2-lite", ""}
	for _, m := range yes {
		if !supportsAdaptiveThinking(m) {
			t.Errorf("supportsAdaptiveThinking(%q) = false, want true", m)
		}
	}
	for _, m := range no {
		if supportsAdaptiveThinking(m) {
			t.Errorf("supportsAdaptiveThinking(%q) = true, want false", m)
		}
	}
}

// A value beyond the model's own cap used to be forwarded verbatim; the
// shipped agent.olium.max_tokens default was 1000000, i.e. an instant 400.
func TestAnthropicMaxTokensIgnoresOutOfRange(t *testing.T) {
	if got := anthropicMaxTokens(Request{MaxTokens: 1000000}); got != defaultAnthropicMaxTokens {
		t.Errorf("max_tokens = %d, want the default %d for an out-of-range request", got, defaultAnthropicMaxTokens)
	}
	if got := anthropicMaxTokens(Request{MaxTokens: maxAnthropicMaxTokens}); got != maxAnthropicMaxTokens {
		t.Errorf("max_tokens = %d, want %d", got, maxAnthropicMaxTokens)
	}
}
