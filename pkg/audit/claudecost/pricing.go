// Package claudecost computes estimated token usage and USD cost for an
// vigolium-audit run by parsing the Claude CLI's stream-json transcript.
//
// Scope: Claude backend only. Codex does not emit per-turn usage
// events on the same shape, so it's out of scope here.
package claudecost

import "strings"

// Pricing describes the per-million-token rates for a single model.
// All rates are in USD per 1,000,000 tokens.
type Pricing struct {
	Model                   string
	InputUSDPerMTok         float64
	OutputUSDPerMTok        float64
	CacheReadUSDPerMTok     float64
	CacheCreate5mUSDPerMTok float64
	CacheCreate1hUSDPerMTok float64
}

// defaultPricing is the fallback when no model-specific entry matches.
// Deliberately the most expensive tier we know of (Opus 4.x) so an
// unrecognised model id over-reports rather than silently reporting $0 or
// under-billing a run the operator is about to pay for.
var defaultPricing = Pricing{
	Model:                   "default",
	InputUSDPerMTok:         15.00,
	OutputUSDPerMTok:        75.00,
	CacheReadUSDPerMTok:     1.50,
	CacheCreate5mUSDPerMTok: 18.75,
	CacheCreate1hUSDPerMTok: 30.00,
}

// tier builds a pricing row from the three numbers the price list actually
// quotes. Cache writes are fixed multiples of the input rate (1.25x for the
// 5m TTL, 2x for 1h), so deriving them keeps the rule enforced rather than
// re-typed nine times.
func tier(model string, in, out, cacheRead float64) Pricing {
	return Pricing{
		Model:                   model,
		InputUSDPerMTok:         in,
		OutputUSDPerMTok:        out,
		CacheReadUSDPerMTok:     cacheRead,
		CacheCreate5mUSDPerMTok: in * 1.25,
		CacheCreate1hUSDPerMTok: in * 2,
	}
}

// pricingTable is a small, prefix-matched list. The first entry whose Model
// field is a prefix of the actual model string wins. Ordering matters —
// place more specific prefixes before less specific ones (claude-opus-5-5
// before claude-opus-5, claude-fable-5-1 before claude-fable-5).
var pricingTable = []Pricing{
	tier("claude-fable-5-1", 10, 50, 0.25), // cheaper cache read than Fable 5
	tier("claude-fable-5", 10, 50, 1.00),   // also Mythos 5.x, same tier
	tier("claude-opus-5-5", 4, 20, 0.20),
	tier("claude-opus-5", 5, 25, 0.50),
	tier("claude-sonnet-5", 2, 10, 0.20),
	tier("claude-opus-4", 15, 75, 1.50),  // claude-opus-4-7, -4-7[1m], ...
	tier("claude-sonnet-4", 3, 15, 0.30), // claude-sonnet-4-6, ...
	tier("claude-haiku-4", 1, 5, 0.10),   // claude-haiku-4-5, ...
}

// PricingFor returns the pricing row that best matches the given model
// identifier by prefix. Returns defaultPricing when no entry matches.
func PricingFor(model string) Pricing {
	m := strings.ToLower(strings.TrimSpace(model))
	for _, p := range pricingTable {
		if strings.HasPrefix(m, p.Model) {
			return p
		}
	}
	return defaultPricing
}

// Usage captures the aggregated token counts produced by a single Claude
// session (main agent or a subagent).
type Usage struct {
	InputTokens       int64 `json:"input_tokens"`
	OutputTokens      int64 `json:"output_tokens"`
	CacheReadTokens   int64 `json:"cache_read_tokens"`
	CacheCreateTokens int64 `json:"cache_create_tokens"`

	// CacheCreate5mTokens and CacheCreate1hTokens, when non-zero, give a
	// more accurate breakdown for pricing. If both are zero but
	// CacheCreateTokens is not, the whole thing is priced at the 5m rate
	// (which is the more common default).
	CacheCreate5mTokens int64 `json:"cache_create_5m_tokens,omitempty"`
	CacheCreate1hTokens int64 `json:"cache_create_1h_tokens,omitempty"`
}

// Add sums another Usage into u in place.
func (u *Usage) Add(o Usage) {
	u.InputTokens += o.InputTokens
	u.OutputTokens += o.OutputTokens
	u.CacheReadTokens += o.CacheReadTokens
	u.CacheCreateTokens += o.CacheCreateTokens
	u.CacheCreate5mTokens += o.CacheCreate5mTokens
	u.CacheCreate1hTokens += o.CacheCreate1hTokens
}

// Price applies the given model's pricing to this usage and returns the
// estimated cost in USD.
func (u Usage) Price(model string) float64 {
	p := PricingFor(model)
	// Prefer the explicit 5m/1h breakdown when available; fall back to
	// treating CacheCreateTokens as 5m cache (the common case).
	create5m := u.CacheCreate5mTokens
	create1h := u.CacheCreate1hTokens
	if create5m == 0 && create1h == 0 {
		create5m = u.CacheCreateTokens
	}
	usd := float64(u.InputTokens)*p.InputUSDPerMTok +
		float64(u.OutputTokens)*p.OutputUSDPerMTok +
		float64(u.CacheReadTokens)*p.CacheReadUSDPerMTok +
		float64(create5m)*p.CacheCreate5mUSDPerMTok +
		float64(create1h)*p.CacheCreate1hUSDPerMTok
	return usd / 1_000_000.0
}
