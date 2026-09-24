package engine

import "github.com/vigolium/vigolium/pkg/olium/stream"

// EventType is the union of engine-emitted event kinds. These are a
// superset of the provider's stream events: the engine forwards text /
// thinking / tool-call events from the provider and adds its own
// tool-execution and turn-lifecycle events.
type EventType string

const (
	// Forwarded from the provider.
	EventTextDelta     EventType = "text_delta"
	EventThinkingDelta EventType = "thinking_delta"
	EventToolCallStart EventType = "toolcall_start" // model began a tool call (unexecuted)

	// Emitted by the engine.
	EventToolExecStart    EventType = "tool_exec_start"    // engine about to run a tool
	EventToolExecProgress EventType = "tool_exec_progress" // tool streaming partial output
	EventToolExecEnd      EventType = "tool_exec_end"      // tool finished
	EventTurnDone         EventType = "turn_done"          // assistant turn complete (model finished this request)
	EventRunDone          EventType = "run_done"           // full run complete (no more tool calls pending)
	EventError            EventType = "error"
	// EventInfo carries a non-fatal engine-level notice (e.g. "transient
	// upstream stream error; retrying"). Message lives in Delta. Consumers
	// that don't recognize this type silently drop it — backward compatible.
	EventInfo EventType = "info"
)

// Event is the single value type emitted on the engine event channel.
type Event struct {
	Type EventType `json:"type"`

	// Text / thinking payloads.
	Delta string `json:"delta,omitempty"`

	// Tool events.
	ToolCallID   string         `json:"tool_call_id,omitempty"`
	ToolName     string         `json:"tool_name,omitempty"`
	ToolCategory string         `json:"tool_category,omitempty"` // tool.CategoryBuiltin / tool.CategoryVigolium
	ToolArgs     map[string]any `json:"tool_args,omitempty"`
	ToolResult   string         `json:"tool_result,omitempty"`
	ToolIsErr    bool           `json:"tool_is_error,omitempty"`

	// Turn / run lifecycle.
	StopReason stream.StopReason `json:"stop_reason,omitempty"`
	Usage      *stream.Usage     `json:"usage,omitempty"`

	// ToolCalls carries the model's tool calls for the just-completed turn.
	// Populated only on EventTurnDone, and only when the turn produced tool
	// calls. It exists so out-of-band consumers (the Pi-style JSONL session
	// transcript in pkg/olium/sessionlog) can render a complete assistant
	// message with full tool arguments without reconstructing them from the
	// argument-less EventToolCallStart events — arguments are only known once
	// the provider stream resolves, which is after the start event fires.
	// Live UI / tool-log consumers ignore this field.
	ToolCalls []stream.ToolCall `json:"tool_calls,omitempty"`

	// Stalled is set on EventRunDone when the run ended because the model
	// kept answering with text-only turns after every empty-turn nudge was
	// spent, as opposed to finishing on its own. Consumers use it to report
	// the stop honestly instead of as a natural completion.
	Stalled bool `json:"stalled,omitempty"`

	// BudgetExhausted marks an EventError that is a budget ceiling rather
	// than a failure - the turn or tool-call cap. The caller should finalize
	// the run (summary, triage, bookkeeping) as it would for any other
	// budget stop. Carried as a field so consumers don't classify a terminal
	// reason by string-matching an error this package formatted itself.
	BudgetExhausted bool `json:"budget_exhausted,omitempty"`

	// Error payload.
	Err string `json:"error,omitempty"`
}

// EventRecorder receives a copy of every engine Event, plus the initiating
// user prompt, so an out-of-band consumer — notably the Pi-style JSONL
// session transcript in pkg/olium/sessionlog — can persist a run without
// coupling into the engine's many event-emission sites or any consumer's
// drain loop. The engine feeds a single recorder sequentially from one
// goroutine per Run, so implementations need not be reentrant; they may,
// however, be called across successive Run calls on the same Engine (the
// interactive TUI reuses one Engine for a whole session).
//
// A recorder that also implements io.Closer is closed by Engine.CloseRecorder.
type EventRecorder interface {
	// UserPrompt is invoked once at the start of each Run with the prompt
	// text that seeds the turn, before any event is emitted.
	UserPrompt(prompt string)
	// Record is invoked for every Event the engine emits, in order, before
	// the event is forwarded on the public Run channel.
	Record(ev Event)
}
