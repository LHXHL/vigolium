package provider

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// An assistant turn that only carries tool calls has empty text. Strict
// openai-compatible gateways (Open WebUI's pydantic OpenAIChatCompletionForm)
// reject any message missing the `content` key with a 400, so every message
// must serialize it even when empty.
func TestBuildOpenAIRequest_AlwaysSendsContentKey(t *testing.T) {
	body := buildOpenAIRequest(Request{
		Model: "m",
		Messages: []Message{
			{Role: RoleUser, Text: "go"},
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "c1", Name: "list_records", Args: map[string]any{"q": "x"}}}},
			{Role: RoleTool, ToolCallID: "c1", Content: ""},
		},
	})
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Messages []map[string]json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Messages) != 3 {
		t.Fatalf("got %d messages, want 3", len(decoded.Messages))
	}
	for i, m := range decoded.Messages {
		c, ok := m["content"]
		if !ok {
			t.Fatalf("messages[%d] (%s) has no content key: %s", i, m["role"], raw)
		}
		if string(c) == "null" {
			t.Fatalf("messages[%d] content is null, want a string", i)
		}
	}
}

func TestBuildOpenAIRequest_NilToolArgsSendEmptyObject(t *testing.T) {
	body := buildOpenAIRequest(Request{Messages: []Message{
		{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "c1", Name: "halt_scan"}}},
	}})
	if got := body.Messages[0].ToolCalls[0].Function.Arguments; got != "{}" {
		t.Fatalf("arguments = %q, want {}", got)
	}
}

// vLLM/DeepSeek stream reasoning as `reasoning_content`, Ollama/OpenRouter as
// `reasoning`; both must surface as thinking, never as answer text.
func TestOpenAIStream_ReasoningDeltasBecomeThinking(t *testing.T) {
	for _, key := range []string{"reasoning_content", "reasoning"} {
		t.Run(key, func(t *testing.T) {
			events := sseStream(t, `data: {"choices":[{"delta":{"`+key+`":"let me think"}}]}

data: {"choices":[{"delta":{"content":"answer"},"finish_reason":"stop"}]}

data: [DONE]

`)
			var thinking, text string
			for _, ev := range events {
				switch ev.Type {
				case stream.EventThinkingDelta:
					thinking += ev.Delta
				case stream.EventTextDelta:
					text += ev.Delta
				}
			}
			if thinking != "let me think" || text != "answer" {
				t.Fatalf("thinking=%q text=%q", thinking, text)
			}
		})
	}
}

// Ollama/Open WebUI/LiteLLM report a failure after the 200 as an SSE frame
// with `error`. It must surface as a stream error, not an empty turn.
func TestOpenAIStream_InStreamErrorFrameIsAnError(t *testing.T) {
	for name, frame := range map[string]string{
		"object": `{"error":{"message":"model runner crashed","type":"server_error"}}`,
		"string": `{"error":"context length exceeded"}`,
		"detail": `{"error":{"detail":"upstream timeout"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			events := sseStream(t, `data: {"choices":[{"delta":{"content":"par"}}]}

data: `+frame+`

`)
			last := events[len(events)-1]
			if last.Type != stream.EventError || !strings.Contains(last.Err, "upstream error in stream") {
				t.Fatalf("want a stream error, got %+v", events)
			}
		})
	}
}
