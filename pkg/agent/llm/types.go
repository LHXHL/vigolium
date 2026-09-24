package llm

// Message represents a single chat message.
type Message struct {
	Role    string // "system", "user", or "assistant"
	Content string
}

// CompletionRequest holds parameters for a completion call.
type CompletionRequest struct {
	Messages  []Message
	Model     string // optional override; uses config default if empty
	MaxTokens int    // optional; 0 = the provider's default ceiling
	// Temperature is accepted for backward compatibility and ignored.
	// Current Claude models reject sampling parameters outright (a 400), and
	// olium's provider layer exposes no per-provider sampling knob, so
	// forwarding this would break the default backend rather than tune it.
	Temperature float64
	JSONSchema  string // optional; enables structured JSON output
}

// CompletionResponse holds the result of a completion call.
type CompletionResponse struct {
	Content   string // raw text (or JSON string when JSONSchema was set)
	Model     string // model actually used
	TokensIn  int    // input tokens consumed
	TokensOut int    // output tokens generated
}
