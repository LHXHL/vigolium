package engine

import "github.com/vigolium/vigolium/pkg/olium/provider"

// History shapes that strict chat templates reject. The Anthropic API merges
// or tolerates them, but Mistral/Mixtral and Gemma templates on vLLM and
// llama.cpp raise "Conversation roles must alternate", and the Mistral API
// and LiteLLM-fronted backends refuse an assistant message that has neither
// content nor tool calls - so one bad turn left the session unusable.

// noResponseText stands in for an assistant turn that produced nothing: only
// reasoning, a response cut by the repetition guard before any text, or a
// server that returned empty content.
const noResponseText = "(no response)"

// appendUserTurn adds a user message, folding it into a trailing user message
// instead of creating a second one in a row. That happens when a previous Run
// failed or was cancelled before the model answered.
func appendUserTurn(history []provider.Message, text string) []provider.Message {
	if n := len(history); n > 0 && history[n-1].Role == provider.RoleUser {
		merged := history[n-1]
		if merged.Text == "" {
			merged.Text = text
		} else if text != "" {
			merged.Text += "\n\n" + text
		}
		history[n-1] = merged
		return history
	}
	return append(history, provider.Message{Role: provider.RoleUser, Text: text})
}

// assistantTurnText is the text to commit for an assistant turn, never empty
// when the turn also has no tool calls.
func assistantTurnText(text string, calls []provider.ToolCall) string {
	if text == "" && len(calls) == 0 {
		return noResponseText
	}
	return text
}
