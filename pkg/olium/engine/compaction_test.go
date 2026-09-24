package engine

import (
	"fmt"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/provider"
)

// buildHistory returns turns of (assistant with one tool call, tool result
// of resultBytes) for compaction tests.
func buildHistory(turns, resultBytes int) []provider.Message {
	var h []provider.Message
	for i := 0; i < turns; i++ {
		id := fmt.Sprintf("call_%d", i)
		h = append(h,
			provider.Message{Role: provider.RoleAssistant, ToolCalls: []provider.ToolCall{{ID: id, Name: "query_records"}}},
			provider.Message{Role: provider.RoleTool, ToolCallID: id, Content: strings.Repeat("X", resultBytes)},
		)
	}
	return h
}

// TestCompactHistoryPreservesShape is the invariant that matters: compaction
// may shrink content but must never drop a message, because every provider
// rejects a turn whose tool calls aren't all answered.
func TestCompactHistoryPreservesShape(t *testing.T) {
	eng := New(Config{MaxHistoryBytes: 40 << 10})
	eng.history = buildHistory(40, 4<<10) // ~160 KiB, well over budget
	before := len(eng.history)

	if !eng.compactHistory() {
		t.Fatal("expected compaction to elide something")
	}
	if len(eng.history) != before {
		t.Errorf("compaction dropped messages: %d -> %d", before, len(eng.history))
	}

	answered := map[string]int{}
	var calls []string
	for _, m := range eng.history {
		switch m.Role {
		case provider.RoleAssistant:
			for _, tc := range m.ToolCalls {
				calls = append(calls, tc.ID)
			}
		case provider.RoleTool:
			answered[m.ToolCallID]++
		}
	}
	for _, id := range calls {
		if answered[id] != 1 {
			t.Errorf("tool call %q has %d results after compaction, want 1", id, answered[id])
		}
	}

	total := 0
	for _, m := range eng.history {
		total += len(m.Text) + len(m.Content)
	}
	if total > eng.maxHistoryBytes {
		t.Errorf("still %d bytes after compaction, budget %d", total, eng.maxHistoryBytes)
	}
}

// TestCompactHistoryKeepsRecentTurns pins that the working set survives -
// eliding what the model is currently reasoning about would be worse than
// the overflow.
func TestCompactHistoryKeepsRecentTurns(t *testing.T) {
	eng := New(Config{MaxHistoryBytes: 8 << 10})
	eng.history = buildHistory(40, 4<<10)
	eng.compactHistory()

	kept := 0
	for i := len(eng.history) - 1; i >= 0 && kept < compactionKeepRecentTurns; i-- {
		m := eng.history[i]
		if m.Role != provider.RoleTool {
			continue
		}
		if strings.Contains(m.Content, "elided") {
			t.Errorf("recent tool result at %d was elided: %q", i, m.Content)
		}
		kept++
	}
}

// TestCompactHistoryNoopUnderBudget guards the common case: a short run must
// not be touched at all.
func TestCompactHistoryNoopUnderBudget(t *testing.T) {
	eng := New(Config{MaxHistoryBytes: 1 << 20})
	eng.history = buildHistory(4, 1<<10)
	snapshot := make([]provider.Message, len(eng.history))
	copy(snapshot, eng.history)

	if eng.compactHistory() {
		t.Error("compaction ran under budget")
	}
	for i := range snapshot {
		if eng.history[i].Content != snapshot[i].Content {
			t.Errorf("message %d changed under budget", i)
		}
	}
}

// TestCompactHistoryDisabled covers the opt-out.
func TestCompactHistoryDisabled(t *testing.T) {
	eng := New(Config{MaxHistoryBytes: -1})
	eng.history = buildHistory(40, 4<<10)
	if eng.compactHistory() {
		t.Error("compaction ran while disabled")
	}
}

// TestElideToolResultKeepsSpillPointer: a spilled result's pointer line is
// the only way back to the full output, so eliding must not take it.
func TestElideToolResultKeepsSpillPointer(t *testing.T) {
	body := strings.Repeat("Y", 5000) +
		"\n\n[120000 bytes total; this is the first 5000. Full output saved to `/tmp/x.txt` — read with `" +
		spillPointerMarker + "\"/tmp/x.txt\"` if you need more.]"
	got := elideToolResult(body)
	if !strings.Contains(got, "elided") {
		t.Errorf("expected an elision note: %q", got)
	}
	if !strings.Contains(got, spillPointerMarker+`"/tmp/x.txt"`) {
		t.Errorf("spill pointer lost: %q", got)
	}
	if len(got) >= len(body) {
		t.Errorf("elision did not shrink the result: %d -> %d", len(body), len(got))
	}
}

// TestCompactHistoryRecentWindowIsAFloor documents the deliberate limit: the
// last few turns are never elided, so a budget smaller than that working set
// is not reachable. Overflowing by the size of six recent results (at most
// ~96 KiB) beats blinding the model to what it is currently working on.
func TestCompactHistoryRecentWindowIsAFloor(t *testing.T) {
	eng := New(Config{MaxHistoryBytes: 1 << 10}) // far below the working set
	eng.history = buildHistory(40, 4<<10)
	eng.compactHistory()

	elided := 0
	for _, m := range eng.history {
		if strings.Contains(m.Content, "elided") {
			elided++
		}
	}
	if elided != 40-compactionKeepRecentTurns {
		t.Errorf("elided %d results, want every one outside the recent window (%d)", elided, 40-compactionKeepRecentTurns)
	}
}
