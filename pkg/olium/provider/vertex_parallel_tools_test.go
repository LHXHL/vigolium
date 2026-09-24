package provider

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// TestGemini_SynthesizedCallIDsAreUnique covers a turn with two parallel
// calls to the SAME function and no `id` on either part — the shape older
// Gemini revisions emit. A per-name id would make both calls share one id,
// which collides in every id-keyed consumer (the engine's start/end pairing,
// the tool log, the TUI live card) and is a hard 400 when the history is
// replayed to Anthropic or OpenAI.
func TestGemini_SynthesizedCallIDsAreUnique(t *testing.T) {
	out := make(chan stream.Event, 32)
	s := &geminiState{}
	part := func(args string) map[string]any {
		return map[string]any{
			"functionCall": map[string]any{
				"name": "query_records",
				"args": map[string]any{"host": args},
			},
		}
	}
	s.applyPart(part("a.example.test"), out)
	s.applyPart(part("b.example.test"), out)
	close(out)

	var ids []string
	for ev := range out {
		if ev.Type == stream.EventToolCallEnd {
			ids = append(ids, ev.ToolCall.ID)
		}
	}
	if len(ids) != 2 {
		t.Fatalf("got %d tool calls, want 2", len(ids))
	}
	if ids[0] == ids[1] {
		t.Errorf("both calls share id %q — parallel calls to one tool must get distinct ids", ids[0])
	}
	for _, id := range ids {
		if id == "" {
			t.Error("empty synthesized call id")
		}
	}
}

// TestGemini_ParallelToolResultsShareOneContent pins the request shape for a
// turn the model answered with two parallel calls: Gemini matches
// functionResponse parts against the functionCall parts of the turn they
// answer, so both results must land in ONE user content.
func TestGemini_ParallelToolResultsShareOneContent(t *testing.T) {
	req := Request{
		Messages: []Message{
			{Role: RoleUser, Text: "go"},
			{Role: RoleAssistant, ToolCalls: []ToolCall{
				{ID: "c1", Name: "query_records", Args: map[string]any{"host": "a"}},
				{ID: "c2", Name: "web_fetch", Args: map[string]any{"url": "https://example.test/"}},
			}},
			{Role: RoleTool, ToolCallID: "c1", Content: `{"records":0}`},
			{Role: RoleTool, ToolCallID: "c2", Content: "<html></html>"},
			{Role: RoleUser, Text: "continue"},
		},
	}

	body := buildGeminiRequest(req)
	if len(body.Contents) != 4 {
		t.Fatalf("got %d contents, want 4 (user, model, tool-results, user): %+v", len(body.Contents), body.Contents)
	}
	results := body.Contents[2]
	if results.Role != "user" {
		t.Errorf("tool-result content role = %q, want user", results.Role)
	}
	if len(results.Parts) != 2 {
		t.Fatalf("tool results split across contents: got %d parts in one content, want 2", len(results.Parts))
	}
	for i, p := range results.Parts {
		if p.FunctionResponse == nil {
			t.Fatalf("part %d is not a functionResponse: %+v", i, p)
		}
	}
	if got := results.Parts[0].FunctionResponse.Name; got != "query_records" {
		t.Errorf("first response name = %q, want query_records", got)
	}
	if got := results.Parts[1].FunctionResponse.Name; got != "web_fetch" {
		t.Errorf("second response name = %q, want web_fetch", got)
	}
	// A following user message must not be folded into the tool content.
	if body.Contents[3].Role != "user" || len(body.Contents[3].Parts) != 1 {
		t.Errorf("trailing user message mis-merged: %+v", body.Contents[3])
	}
}
