package agent

import (
	"fmt"
	"sync"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/audit/claudecost"
)

// Budget stop kinds, shared with pkg/olium/autopilot's Result.BudgetStop so a
// caller reports one vocabulary whichever loop ran.
const (
	BudgetStopWallTime = "wall_time"
	BudgetStopTokens   = "tokens"
	BudgetStopCost     = "cost"
	BudgetStopCommands = "commands"
)

// RunBudget caps the cumulative spend of every agent call an Engine makes:
// tool calls (--max-commands), input+output tokens (--token-budget) and
// estimated USD cost (--max-cost-usd, priced for Model with claudecost). A
// zero field is no cap. It is charged after each Engine.Run call completes, so
// one call can overshoot by its own spend; the next call is never started.
type RunBudget struct {
	MaxCommands int
	TokenBudget int64
	MaxCostUSD  float64
	Model       string
}

// Active reports whether any cap is set.
func (b RunBudget) Active() bool {
	return b.MaxCommands > 0 || b.TokenBudget > 0 || b.MaxCostUSD > 0
}

// BudgetExhaustedError is the cancellation cause of a run whose RunBudget ran
// out. Stop is one of the BudgetStop* kinds.
type BudgetExhaustedError struct {
	Stop   string
	Reason string
}

func (e *BudgetExhaustedError) Error() string { return e.Reason }

// budgetState is the Engine's running tally against its RunBudget.
type budgetState struct {
	mu          sync.Mutex
	limits      RunBudget
	onExhausted func(*BudgetExhaustedError)
	toolCalls   int
	in, out     int64
	tripped     *BudgetExhaustedError
}

// SetRunBudget installs b on the engine. onExhausted is called once, with the
// first cap crossed — the caller cancels its run context there (typically
// context.WithCancelCause with the error as the cause).
func (e *Engine) SetRunBudget(b RunBudget, onExhausted func(*BudgetExhaustedError)) {
	e.budget.mu.Lock()
	defer e.budget.mu.Unlock()
	e.budget.limits = b
	e.budget.onExhausted = onExhausted
}

// RunBudgetUsage returns the tool calls and estimated cost charged so far.
func (e *Engine) RunBudgetUsage() (toolCalls int, costUSD float64) {
	e.budget.mu.Lock()
	defer e.budget.mu.Unlock()
	return e.budget.toolCalls, e.budget.costLocked()
}

// BudgetExhausted returns the budget stop that tripped, or nil.
func (e *Engine) BudgetExhausted() *BudgetExhaustedError {
	e.budget.mu.Lock()
	defer e.budget.mu.Unlock()
	return e.budget.tripped
}

func (b *budgetState) costLocked() float64 {
	return claudecost.Usage{InputTokens: b.in, OutputTokens: b.out}.Price(b.limits.Model)
}

// chargeRunBudget adds one call's spend and trips the budget when a cap is
// crossed.
func (e *Engine) chargeRunBudget(u agenttypes.TokenUsage, toolCalls int) {
	b := &e.budget
	b.mu.Lock()
	b.toolCalls += toolCalls
	b.in += int64(u.InputTokens)
	b.out += int64(u.OutputTokens)
	if b.tripped != nil || !b.limits.Active() {
		b.mu.Unlock()
		return
	}
	var trip *BudgetExhaustedError
	switch {
	case b.limits.MaxCommands > 0 && b.toolCalls >= b.limits.MaxCommands:
		trip = &BudgetExhaustedError{Stop: BudgetStopCommands,
			Reason: fmt.Sprintf("command budget exhausted (tool calls=%d, cap=%d)", b.toolCalls, b.limits.MaxCommands)}
	case b.limits.TokenBudget > 0 && b.in+b.out > b.limits.TokenBudget:
		trip = &BudgetExhaustedError{Stop: BudgetStopTokens,
			Reason: fmt.Sprintf("token budget exhausted (used=%d, cap=%d)", b.in+b.out, b.limits.TokenBudget)}
	case b.limits.MaxCostUSD > 0 && b.costLocked() > b.limits.MaxCostUSD:
		trip = &BudgetExhaustedError{Stop: BudgetStopCost,
			Reason: fmt.Sprintf("cost budget exhausted (est. $%.4f, cap=$%.4f)", b.costLocked(), b.limits.MaxCostUSD)}
	}
	if trip == nil {
		b.mu.Unlock()
		return
	}
	b.tripped = trip
	cb := b.onExhausted
	b.mu.Unlock()
	if cb != nil {
		cb(trip)
	}
}
