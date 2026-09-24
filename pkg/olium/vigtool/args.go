package vigtool

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// argsString reads a string argument, trimming whitespace. Returns empty
// when the key is missing or not a string.
func argsString(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return strings.TrimSpace(v)
}

// argsStringArray reads a []string from the JSON-decoded args map. Both
// concrete []string and the more common []any-of-strings (after JSON
// unmarshal) are accepted. Empty / non-string entries are dropped.
//
// A bare string is accepted as a one-element list. Models routinely send
// `targets: "https://host"` for an array parameter, and returning nil there
// produced the worst possible error - "'targets' is required and must be
// non-empty" for an argument the model plainly supplied, which reads as a
// tool bug and invites a verbatim retry.
func argsStringArray(args map[string]any, key string) []string {
	switch raw := args[key].(type) {
	case string:
		if s := strings.TrimSpace(raw); s != "" {
			return []string{s}
		}
		return nil
	case []string:
		out := make([]string, 0, len(raw))
		for _, s := range raw {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(raw))
		for _, x := range raw {
			if s, ok := x.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	}
	return nil
}

// argsBool reads a bool argument. Missing / wrong-typed = false.
func argsBool(args map[string]any, key string) bool {
	b, _ := args[key].(bool)
	return b
}

// argsInt reads an integer argument. JSON decoders surface numbers as
// float64 by default, so we unwrap whichever shape arrived.
func argsInt(args map[string]any, key string) int {
	switch n := args[key].(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	}
	return 0
}

// argsIntArray reads an []int from JSON-decoded args. Accepts []float64
// (JSON default), []int, and []any-of-numbers, plus a bare number as a
// one-element list (see argsStringArray for why). Non-numeric entries are
// silently dropped.
func argsIntArray(args map[string]any, key string) []int {
	switch raw := args[key].(type) {
	case float64:
		return []int{int(raw)}
	case int:
		return []int{raw}
	case int64:
		return []int{int(raw)}
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
			return []int{n}
		}
		return nil
	case []int:
		out := make([]int, 0, len(raw))
		return append(out, raw...)
	case []float64:
		out := make([]int, 0, len(raw))
		for _, n := range raw {
			out = append(out, int(n))
		}
		return out
	case []any:
		out := make([]int, 0, len(raw))
		for _, x := range raw {
			switch n := x.(type) {
			case float64:
				out = append(out, int(n))
			case int:
				out = append(out, n)
			case int64:
				out = append(out, int(n))
			case string:
				// `status: ["200"]` is a common shape. Dropping it silently
				// left the caller with an empty filter, which returns
				// everything - a wrong answer rather than an error.
				if v, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
					out = append(out, v)
				}
			}
		}
		return out
	}
	return nil
}

// formatRFC3339 returns t in UTC RFC3339, or "" for the zero value. Used by
// every summarize* helper in this package — extracted so the IsZero guard
// isn't copy-pasted six times.
func formatRFC3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// scanFinalizeReserve is how much of a tool's budget is held back from the
// scan itself so the runner can finalize the scan row and the tool can read
// it back before the engine's per-tool deadline cancels everything.
const scanFinalizeReserve = 20 * time.Second

// scanBudget derives the wall-clock cap to hand the runner as
// ScanMaxDuration. An unbounded scan under a deadline-bearing tool context
// gets hard-cancelled mid-phase: the scan row is never finalized and the
// agent receives an all-zero summary it cannot distinguish from a clean
// empty result. Bounding the scan just inside the deadline lets it stop
// early, finalize, and report whatever it did find.
func scanBudget(ctx context.Context, want time.Duration) time.Duration {
	return tool.BudgetFrom(ctx, want, scanFinalizeReserve)
}

// scanTool carries the wall-clock budget a scan-launching tool declares to
// the engine (tool.LongRunning) and hands to the runner. Embedding it keeps
// the two in step: a tool that declared 30m and then passed the runner an
// unrelated number would be cut off mid-scan by its own deadline.
type scanTool struct{ max time.Duration }

// MaxDuration implements tool.LongRunning - a full scan is categorically
// longer than the engine's default per-tool deadline.
func (s scanTool) MaxDuration() time.Duration { return s.max }

// budget is the cap to pass the runner as LaunchParams.ScanMaxDuration.
func (s scanTool) budget(ctx context.Context) time.Duration { return scanBudget(ctx, s.max) }
