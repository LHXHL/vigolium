package autopilot

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// toolLoopProvider never halts: every turn calls the read-only ls tool and
// reports a fixed usage, so only a budget can end the run.
type toolLoopProvider struct{ in, out int }

func (toolLoopProvider) Name() string { return "tool-loop" }

func (p toolLoopProvider) Stream(ctx context.Context, _ provider.Request) (<-chan stream.Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ch := make(chan stream.Event, 8)
	go func() {
		defer close(ch)
		ch <- stream.Event{Type: stream.EventToolCallStart, ToolCall: &stream.ToolCall{ID: "c", Name: "ls"}}
		ch <- stream.Event{Type: stream.EventToolCallEnd, ToolCall: &stream.ToolCall{ID: "c", Name: "ls", Arguments: map[string]any{"path": "."}}}
		ch <- stream.Event{Type: stream.EventDone, StopReason: stream.StopReasonToolUse, Usage: &stream.Usage{Input: p.in, Output: p.out}}
	}()
	return ch, nil
}

func runBudgeted(t *testing.T, opts Options) *Result {
	t.Helper()
	t.Setenv("HOME", t.TempDir()) // never read the operator's ~/.vigolium
	opts.Provider = toolLoopProvider{in: 1000, out: 500}
	opts.Model = "claude-sonnet-4"
	opts.Out = io.Discard
	opts.ToolLog = io.Discard
	opts.NoSkillFilter = true
	opts.SourcePath = t.TempDir()
	if opts.MaxTurns == 0 {
		opts.MaxTurns = 50
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := Run(ctx, opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

// TestRunStopsOnTokenBudget: a token cap halts the loop with BudgetStop
// "tokens" instead of running to the turn ceiling.
func TestRunStopsOnTokenBudget(t *testing.T) {
	res := runBudgeted(t, Options{TokenBudget: 2_000})
	if res.BudgetStop != BudgetTokens {
		t.Fatalf("BudgetStop = %q, want %q (halt: %s)", res.BudgetStop, BudgetTokens, res.HaltReason)
	}
	// Checked after each turn; a turn already in flight may still land, but the
	// run must stop far short of its 50-turn ceiling (75k tokens).
	if used := res.InputTokens + res.OutputTokens; used > 15_000 {
		t.Errorf("used %d tokens; the 2000-token cap did not stop the run", used)
	}
}

// TestRunStopsOnCostBudget: the running cost estimate is checked every turn.
func TestRunStopsOnCostBudget(t *testing.T) {
	res := runBudgeted(t, Options{MaxCostUSD: 0.01})
	if res.BudgetStop != BudgetCost {
		t.Fatalf("BudgetStop = %q, want %q (halt: %s)", res.BudgetStop, BudgetCost, res.HaltReason)
	}
	if res.CostUSD <= 0.01 {
		t.Errorf("CostUSD = %f, want it past the 0.01 cap that stopped the run", res.CostUSD)
	}
}
