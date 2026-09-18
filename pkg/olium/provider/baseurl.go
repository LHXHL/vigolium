package provider

import "strings"

// The two compatible providers (openai-compatible, anthropic-compatible) point
// at an operator-supplied base_url, and operators write it three ways: the full
// endpoint, the /v1 root their server's docs show, or a bare host. Each
// provider used to answer that in its own switch, and the switches drifted —
// one treated any path as a deliberate mount point, the other only a trailing
// /v1 — so the same gateway URL resolved differently depending on which
// protocol it spoke.
const (
	// versionSegment is the API version path both vendors mount under.
	versionSegment = "/v1"
	// openAIChatEndpoint and anthropicMessagesEndpoint are the per-protocol
	// endpoint suffixes, relative to that version root.
	openAIChatEndpoint        = "/chat/completions"
	anthropicMessagesEndpoint = "/messages"
)

// normalizeProviderBaseURL resolves raw to a complete endpoint URL: it is
// returned as-is when it already names the endpoint, gets endpoint appended
// when it names the version root, and gets /v1 + endpoint otherwise. Trailing
// slashes are trimmed so we never emit `/v1//messages`. An empty raw stays
// empty — the caller decides what an unset base_url means.
//
// The last case is a guess: a server can mount the API anywhere, and the URL
// text doesn't say. toggleVersionSegment is what makes the guess cheap to be
// wrong about.
func normalizeProviderBaseURL(raw, endpoint string) string {
	u := strings.TrimRight(strings.TrimSpace(raw), "/")
	switch {
	case u == "":
		return ""
	case strings.HasSuffix(u, endpoint):
		return u
	case strings.HasSuffix(u, versionSegment):
		return u + endpoint
	default:
		return u + versionSegment + endpoint
	}
}

// toggleVersionSegment returns the same endpoint URL with its /v1 segment
// added or removed — the other spelling to try when the configured one 404s.
// It returns "" for a URL that doesn't end in endpoint, which has no second
// spelling worth trying.
func toggleVersionSegment(u, endpoint string) string {
	prefix, ok := strings.CutSuffix(u, endpoint)
	if !ok {
		return ""
	}
	if trimmed, versioned := strings.CutSuffix(prefix, versionSegment); versioned {
		return trimmed + endpoint
	}
	return prefix + versionSegment + endpoint
}
