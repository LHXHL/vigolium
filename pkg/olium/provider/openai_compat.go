package provider

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
)

// Response shapes that openai-compatible servers (Ollama, llama.cpp, vLLM,
// LM Studio, LiteLLM, Open WebUI) send in place of the canonical streaming
// chat-completions format. Each one used to be dropped silently, turning a
// real answer or tool call into an empty turn.

// maxToolArgsInError caps how much of a malformed arguments string (or an
// unparseable body) is echoed into an error.
const maxToolArgsInError = 500

// fallbackCallSeq numbers the ids given to tool calls that arrive without
// one. Process-wide so ids stay unique across turns and engines.
var fallbackCallSeq atomic.Uint64

// fallbackCallID returns a unique id for a tool call the server sent without
// one (llama.cpp, older Ollama, some gateways). Assigned when the call first
// appears, so the start event, the end event, the history entry and the tool
// result all carry the same id; an empty id is rejected by strict endpoints
// and cannot be joined by id-keyed consumers (tool log, TUI cards).
func fallbackCallID() string {
	return fmt.Sprintf("call_vig_%d", fallbackCallSeq.Add(1))
}

// decodeToolArguments parses the accumulated arguments string of one tool
// call. It accepts the double-encoded form small local models often emit (a
// JSON string whose content is the object). On failure it returns an empty
// map plus a description of the problem for the model: running the tool with
// {} made it fail with "X is required" while history claimed the model had
// sent {}, so the model never saw what was actually wrong.
func decodeToolArguments(raw string) (map[string]any, string) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "null" {
		return map[string]any{}, ""
	}
	var args map[string]any
	err := json.Unmarshal([]byte(trimmed), &args)
	if err == nil {
		if args == nil {
			args = map[string]any{}
		}
		return args, ""
	}
	var inner string
	if json.Unmarshal([]byte(trimmed), &inner) == nil {
		if json.Unmarshal([]byte(strings.TrimSpace(inner)), &args) == nil && args != nil {
			return args, ""
		}
	}
	return map[string]any{}, fmt.Sprintf("arguments are not a valid JSON object (%v): %s", err, truncateInline(trimmed, maxToolArgsInError))
}

// toolArgs decodes a finished tool call's arguments for any driver, logging
// a parse failure under --debug as before.
func toolArgs(label, raw string) (map[string]any, string) {
	args, argsErr := decodeToolArguments(raw)
	if argsErr != "" {
		debugToolArgErr(label, errors.New(argsErr))
	}
	return args, argsErr
}

// joinTextParts flattens `content` sent as an array of parts
// ([{"type":"text","text":"..."}], as Mistral and some LiteLLM routes do)
// into the plain string the rest of the driver expects.
func joinTextParts(parts []any) string {
	var b strings.Builder
	for _, p := range parts {
		switch part := p.(type) {
		case string:
			b.WriteString(part)
		case map[string]any:
			if t, ok := part["text"].(string); ok {
				b.WriteString(t)
			}
		}
	}
	return b.String()
}

// normalizeOpenAIDelta rewrites the non-canonical field shapes in one delta
// (or non-streamed message) in place: array content becomes a string, and
// tool-call arguments sent as a JSON object (LiteLLM over native Ollama)
// become the JSON string the accumulator concatenates.
func normalizeOpenAIDelta(delta map[string]any) {
	if parts, ok := delta["content"].([]any); ok {
		delta["content"] = joinTextParts(parts)
	}
	tcs, _ := delta["tool_calls"].([]any)
	for _, raw := range tcs {
		tc, _ := raw.(map[string]any)
		fn, _ := tc["function"].(map[string]any)
		if fn == nil {
			continue
		}
		switch fn["arguments"].(type) {
		case string, nil:
		default:
			if b, err := json.Marshal(fn["arguments"]); err == nil {
				fn["arguments"] = string(b)
			}
		}
	}
}

// sniffJSONBody reports whether a 200 response is a plain JSON document
// rather than an event stream - a proxy or pipe that ignores stream:true, or
// a gateway that reports an error as a 200 JSON body. SSE never starts with
// '{' or '['. It peeks one byte at a time so a slow stream is not held back
// waiting for a larger buffer to fill. The returned body replays the peeked
// bytes.
func sniffJSONBody(body io.ReadCloser) (io.ReadCloser, bool) {
	br := bufio.NewReader(body)
	wrapped := struct {
		io.Reader
		io.Closer
	}{br, body}
	for i := 0; i < 64; i++ {
		b, err := br.Peek(i + 1)
		if err != nil {
			return wrapped, false
		}
		switch c := b[i]; c {
		case ' ', '\t', '\r', '\n':
			continue
		case '{', '[':
			return wrapped, true
		default:
			return wrapped, false
		}
	}
	return wrapped, false
}

// maxJSONCompletionBytes bounds a non-streamed completion body.
const maxJSONCompletionBytes = 32 << 20

// readJSONCompletion decodes a non-streamed chat completion (or a 200 error
// body) for consumeJSON, returning the raw bytes alongside for error decoding.
func readJSONCompletion(body io.Reader) (map[string]any, []byte, error) {
	raw, err := io.ReadAll(io.LimitReader(body, maxJSONCompletionBytes))
	if err != nil {
		return nil, nil, err
	}
	raw = bytes.TrimSpace(raw)
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, raw, fmt.Errorf("200 response is neither an event stream nor a JSON completion: %s", truncateInline(string(raw), maxToolArgsInError))
	}
	return parsed, raw, nil
}

// rejectsStreamOptions reports whether an error body says the server does not
// accept stream_options (strict pydantic/extra-forbid validators: the Mistral
// API, older Groq, LM Studio and Azure versions).
func rejectsStreamOptions(status int, raw []byte) bool {
	return (status == 400 || status == 422) && bytes.Contains(raw, []byte("stream_options"))
}
