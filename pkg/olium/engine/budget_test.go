package engine

import (
	"context"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// TestMaxToolCallsBudget pins that the tool-call budget bounds calls (not
// turns) and survives Reset - a section rotation must not refill it.
func TestMaxToolCallsBudget(t *testing.T) {
	eng := New(Config{MaxToolCalls: 5})

	if spent := eng.spendToolCalls(3); spent {
		t.Error("3 of 5 should not exhaust the budget")
	}
	if eng.ToolCallCount() != 3 {
		t.Errorf("count = %d, want 3", eng.ToolCallCount())
	}
	// A single turn's parallel calls all count.
	if spent := eng.spendToolCalls(2); !spent {
		t.Error("5 of 5 should exhaust the budget")
	}

	eng.Reset()
	if eng.ToolCallCount() != 5 {
		t.Errorf("Reset refilled the budget: count = %d, want 5 - a section rotation must not hand out a fresh budget", eng.ToolCallCount())
	}
	if spent := eng.spendToolCalls(1); !spent {
		t.Error("budget must stay exhausted after Reset")
	}
}

// TestMaxToolCallsUnlimited covers the default.
func TestMaxToolCallsUnlimited(t *testing.T) {
	eng := New(Config{})
	if spent := eng.spendToolCalls(10_000); spent {
		t.Error("a zero budget means unlimited")
	}
}

// TestBudgetExhaustedIsATypedFlag pins that both ceilings mark the event as
// a budget stop rather than leaving the caller to match the message text.
func TestBudgetExhaustedIsATypedFlag(t *testing.T) {
	reg := tool.NewRegistry()
	reg.Register(&fakeTool{name: "query_findings", out: "ok"})
	reg.Register(&fakeTool{name: "web_fetch", out: "ok"})

	eng := New(Config{Provider: parallelToolProvider{}, Tools: reg, MaxTurns: 5, MaxToolCalls: 1})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var budget, plain int
	for ev := range eng.Run(ctx, "go") {
		if ev.Type == EventError {
			if ev.BudgetExhausted {
				budget++
			} else {
				plain++
			}
		}
	}
	if budget != 1 || plain != 0 {
		t.Errorf("got %d budget errors and %d plain, want 1 and 0", budget, plain)
	}
}
