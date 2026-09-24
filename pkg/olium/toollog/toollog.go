// Package toollog renders engine tool-call events as readable, optionally
// colorized lines for operator-facing tool logs (autopilot stderr, headless
// stderr, swarm phase streams). It pairs Start/End events by ToolCallID so
// the End line can report elapsed time alongside the result size or error.
//
// Output shape (default):
//
//	▶ <tool> <key=value> ...
//	  ✓ <bytes> bytes  (<elapsed>)
//
//	▶ <tool> <key=value> ...
//	  ✗ failed: <reason>  (<elapsed>)
//
// In verbose mode the success line is followed by a short head/tail preview
// of the tool's result so operators can sanity-check what the agent saw
// without enabling full transcript dumping.
//
// Vigolium-domain tools (run_native_scan, report_finding, halt_scan, etc.) render
// the leading arrow and tool name in magenta; generic agent tools (bash,
// web_fetch, …) stay cyan.
//
// Colors come from pkg/terminal and auto-disable when stderr is not a TTY
// or when NO_COLOR is set, so the same writer works for both interactive
// runs and piped log capture.
package toollog

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/tool"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// previewMaxLines and previewMaxChars cap the verbose preview block so
// even an enormous web_fetch body or grep dump stays under a screen.
const (
	previewMaxLines = 6
	previewMaxChars = 400
)

// Logger renders tool-execution events to its writers. The zero value is
// not usable — construct via New. Safe for concurrent Handle calls; the
// per-call elapsed bookkeeping is mutex-guarded.
//
// Three writers are kept on purpose:
//   - w      receives tool lifecycle lines (▶ start / ✓ end / ✗ failed) and
//     is typically stderr.
//   - turnW  receives the per-turn `[turn done in=… out=…]` usage line.
//     Routed to the same stream as the assistant text so the line
//     prints AFTER the model's message without stdout/stderr
//     buffering interleaving the two. Falls back to w when nil.
//   - thinkW receives the muted `⋈ thinking` reasoning block. Defaults to w
//     (the tool-line stream, typically stderr). Override via
//     WithThinkingWriter when the tool-line stream is stdout (swarm) but
//     reasoning should stay on the stderr side channel.
type Logger struct {
	w       io.Writer
	turnW   io.Writer
	thinkW  io.Writer
	verbose bool
	mu      sync.Mutex
	starts  map[string]time.Time
	// think accumulates the current turn's reasoning deltas; flushed as one
	// compacted block before the turn's first tool card / on turn-done /
	// when the caller calls FlushThinking ahead of assistant text. Guarded
	// by mu so concurrent Handle calls stay safe.
	think strings.Builder
}

// New returns a Logger that writes to w. A nil w turns Handle into a no-op,
// so callers can pass an unconditional writer without nil-checks.
func New(w io.Writer) *Logger {
	return NewWith(w, false)
}

// NewWith returns a Logger writing to w for every event type. When verbose
// is true, two extra streams are enabled: the per-tool result preview
// (up to 6 lines or 400 chars of the tool's result, head- or tail-sliced
// per tool — bash uses the tail, others use the head) and the per-turn
// `[turn done in=… out=… cached=…]` usage line. In the default non-verbose
// mode, both are suppressed so a one-shot prompt's output isn't cluttered
// by token accounting next to the assistant's reply.
//
// Use NewWithStreams when the turn-done line needs to land on a different
// writer than the tool-call lines (e.g. on the assistant text stream so
// stdout/stderr buffering can't reorder them).
func NewWith(w io.Writer, verbose bool) *Logger {
	return NewWithStreams(w, w, verbose)
}

// NewWithStreams returns a Logger that splits tool-call lifecycle (start /
// end / preview) onto toolLog and the per-turn usage line onto turnLog.
// Pass the assistant text writer as turnLog so the `[turn done ...]` line
// is guaranteed to print after the message that just ended. A nil turnLog
// folds into toolLog (back-compat with NewWith).
func NewWithStreams(toolLog, turnLog io.Writer, verbose bool) *Logger {
	if turnLog == nil {
		turnLog = toolLog
	}
	return &Logger{w: toolLog, turnW: turnLog, thinkW: toolLog, verbose: verbose, starts: make(map[string]time.Time)}
}

// WithThinkingWriter overrides the writer the muted `⋈ thinking` reasoning
// block is flushed to (default: the tool-line writer w). Use it when tool
// lines go to stdout (e.g. swarm phases mirror assistant text + tool cards to
// stdout) but reasoning should land on the stderr side channel so piped stdout
// stays clean. Returns l for chaining. A nil w falls back to the tool-line
// writer at flush time.
func (l *Logger) WithThinkingWriter(w io.Writer) *Logger {
	if l != nil {
		l.thinkW = w
	}
	return l
}

// Handle dispatches a single engine event. Returns true when the event was
// a tool/turn lifecycle event that the logger consumed (so callers can
// skip their own handling for those types).
func (l *Logger) Handle(ev engine.Event) bool {
	if l == nil || l.w == nil {
		return false
	}
	switch ev.Type {
	case engine.EventToolExecStart:
		l.start(ev)
		return true
	case engine.EventToolExecEnd:
		l.end(ev)
		return true
	case engine.EventTurnDone:
		l.turn(ev)
		return true
	}
	return false
}

// HandleTool is Handle minus the per-turn usage line. Useful for callers
// (e.g. the swarm phase adapter) that drive multiple phase runs against
// the same writer and don't want a `[turn done ...]` echo per phase
// cluttering the user-visible stream.
func (l *Logger) HandleTool(ev engine.Event) bool {
	if l == nil || l.w == nil {
		return false
	}
	switch ev.Type {
	case engine.EventToolExecStart:
		l.start(ev)
		return true
	case engine.EventToolExecEnd:
		l.end(ev)
		return true
	}
	return false
}

// HandleTurn renders only the per-turn `[turn done ...]` usage line.
// Returns true when ev was EventTurnDone (whether or not the line was
// actually written — verbose may be off, or Usage may be nil). Callers
// (autopilot) use this to gate the line on "did the model emit any
// assistant text this turn?", suppressing the lonely accounting line
// that appears when a turn is entirely tool calls.
func (l *Logger) HandleTurn(ev engine.Event) bool {
	if l == nil || l.turnW == nil {
		return false
	}
	if ev.Type != engine.EventTurnDone {
		return false
	}
	l.turn(ev)
	return true
}

// HandleThinking accumulates a model reasoning delta (EventThinkingDelta) for
// the current turn. Returns true when ev was a thinking delta so callers can
// `continue` without their own handling — true even when verbose is off (the
// event is still "consumed", just dropped) so the non-verbose path skips it
// cleanly. Accumulation only happens under verbose; the buffered block is
// emitted by the next start() / turn() / FlushThinking call as a single
// compacted `⋈ thinking` block on thinkW.
func (l *Logger) HandleThinking(ev engine.Event) bool {
	if l == nil {
		return false
	}
	if ev.Type != engine.EventThinkingDelta {
		return false
	}
	// Accumulate only when verbose AND there's somewhere to flush — the
	// reasoning lane is independent of the tool-line writer w (it may be nil,
	// e.g. a query with streaming off, while thinkW is os.Stderr).
	if l.verbose && (l.thinkW != nil || l.w != nil) {
		l.mu.Lock()
		l.think.WriteString(ev.Delta)
		l.mu.Unlock()
	}
	return true
}

// FlushThinking emits any buffered reasoning as a compacted `⋈ thinking` block
// and resets the buffer. Idempotent and safe to call when nothing is buffered.
//
// Flush contract — reasoning is flushed at exactly two kinds of trigger:
//   - before a tool card: start() flushes automatically, so a turn's reasoning
//     reads as the reason for the tool call that follows;
//   - before assistant text: the caller must call FlushThinking itself, since
//     text deltas are written straight to the caller's stream (not through the
//     logger), so the logger can't intercept them. Callers also flush once at
//     run/phase end to surface reasoning from a final turn that produced
//     neither a tool card nor text.
func (l *Logger) FlushThinking() { l.flushThinking() }

// flushThinking pulls the buffered reasoning out under the lock, then renders
// it outside the lock so I/O never blocks a concurrent Handle. No-op on empty
// buffer or when compaction leaves nothing (e.g. all-blank reasoning).
func (l *Logger) flushThinking() {
	if l == nil {
		return
	}
	l.mu.Lock()
	body := l.think.String()
	l.think.Reset()
	l.mu.Unlock()
	if body == "" {
		return
	}
	body = CompactThinking(body)
	if body == "" {
		return
	}
	w := l.thinkW
	if w == nil {
		w = l.w
	}
	if w == nil {
		return
	}
	header := terminal.Muted("  " + terminal.SymbolBowtie + " thinking")
	_, _ = fmt.Fprintf(w, "\n%s\n%s\n", header, terminal.Muted(indentLines(body, "    ")))
}

func (l *Logger) start(ev engine.Event) {
	// Reasoning for this turn precedes its tool calls; flush it first so the
	// `⋈ thinking` block reads as the reason for the tool card that follows.
	l.flushThinking()

	l.mu.Lock()
	l.starts[ev.ToolCallID] = time.Now()
	l.mu.Unlock()

	arrow, name := arrowAndName(ev.ToolCategory, ev.ToolName)
	args := coloredArgs(ev.ToolArgs)
	if args == "" {
		_, _ = fmt.Fprintf(l.w, "\n%s %s\n", arrow, name)
		return
	}
	_, _ = fmt.Fprintf(l.w, "\n%s %s %s\n", arrow, name, args)
}

func (l *Logger) end(ev engine.Event) {
	var elapsed time.Duration
	l.mu.Lock()
	if t, ok := l.starts[ev.ToolCallID]; ok {
		elapsed = time.Since(t)
		delete(l.starts, ev.ToolCallID)
	}
	l.mu.Unlock()

	timing := terminal.Muted("(" + formatElapsed(elapsed) + ")")

	if ev.ToolIsErr {
		reason := summarizeErr(ev.ToolResult)
		_, _ = fmt.Fprintf(l.w, "  %s %s  %s\n",
			terminal.Red("✗"),
			terminal.Red("failed: "+reason),
			timing)
		return
	}
	_, _ = fmt.Fprintf(l.w, "  %s %s  %s\n",
		terminal.Green("✓"),
		fmt.Sprintf("%d bytes", len(ev.ToolResult)),
		timing)

	if l.verbose {
		l.writePreview(ev)
	}
}

func (l *Logger) turn(ev engine.Event) {
	if ev.Usage == nil || !l.verbose {
		return
	}
	// Written to turnW (typically the assistant text stream) so the line
	// always lands AFTER the message text that just finished streaming —
	// stdout/stderr can buffer independently and reorder otherwise.
	// Prefix with ∴ (therefore / result) so the accounting line reads as
	// a conclusion to the planning + tool-call sequence above it. The
	// whole row is gated on verbose mode at the top of the function, so
	// non-verbose runs never see this line.
	_, _ = fmt.Fprintf(l.turnW, "\n%s %s\n",
		terminal.ResultSymbol(),
		terminal.Muted(fmt.Sprintf(
			"[turn done in=%d out=%d cached=%d]",
			ev.Usage.Input, ev.Usage.Output, ev.Usage.CacheRead)))
}

// writePreview emits the head/tail preview block under a successful tool
// result. Only called when verbose is enabled; no-op for empty results so
// noise stays minimal.
func (l *Logger) writePreview(ev engine.Event) {
	body := strings.TrimRight(ev.ToolResult, "\n")
	if body == "" {
		return
	}
	mode := previewMode(ev.ToolName)
	header, lines := slicePreview(body, mode)
	if len(lines) == 0 {
		return
	}
	_, _ = fmt.Fprintf(l.w, "    %s\n", terminal.Muted("… "+header+":"))
	for _, line := range lines {
		_, _ = fmt.Fprintf(l.w, "    %s\n", terminal.Muted(line))
	}
}

// previewSliceMode chooses head vs tail truncation per tool. bash output
// almost always carries the relevant signal in the trailing lines (exit
// code, last log entries, command result); most other tools front-load
// the interesting content.
type previewSliceMode int

const (
	previewHead previewSliceMode = iota // first N lines
	previewTail                         // last N lines
)

// previewMode returns the slicing strategy for a given tool. Unknown
// names default to previewHead — first N lines is the safer guess for
// arbitrary output.
func previewMode(toolName string) previewSliceMode {
	switch toolName {
	case "bash":
		return previewTail
	default:
		return previewHead
	}
}

// slicePreview returns the header label ("first lines" / "last lines")
// and up to previewMaxLines lines of body, capped at previewMaxChars
// total characters across the slice. Trailing whitespace on each line is
// preserved so indented payloads (HTML, JSON) look right.
func slicePreview(body string, mode previewSliceMode) (string, []string) {
	all := strings.Split(body, "\n")
	if mode == previewTail {
		return "last lines", takeBudget(tailLines(all, previewMaxLines), previewMaxChars)
	}
	return "first lines", takeBudget(headLines(all, previewMaxLines), previewMaxChars)
}

func headLines(all []string, n int) []string {
	if len(all) <= n {
		return all
	}
	return all[:n]
}

func tailLines(all []string, n int) []string {
	if len(all) <= n {
		return all
	}
	return all[len(all)-n:]
}

// takeBudget caps the rendered preview so a single ultra-long line can't
// blow past the character budget. Lines are kept whole; the last line
// that would exceed the budget is truncated with an ellipsis.
func takeBudget(lines []string, maxChars int) []string {
	out := make([]string, 0, len(lines))
	used := 0
	for _, line := range lines {
		remaining := maxChars - used
		if remaining <= 0 {
			break
		}
		if len(line) <= remaining {
			out = append(out, line)
			used += len(line) + 1 // +1 for the implicit newline
			continue
		}
		// Last line: truncate with ellipsis. We still emit it so the
		// preview shows *something* of the line rather than ending mid-block.
		out = append(out, line[:remaining-1]+"…")
		break
	}
	return out
}

// arrowAndName picks the leading-arrow color and the tool-name color
// based on the tool's declared category. Vigolium-domain tools render
// magenta; everything else stays cyan.
func arrowAndName(category, toolName string) (string, string) {
	if category == tool.CategoryVigolium {
		return terminal.Magenta(terminal.SymbolStart), terminal.BoldMagenta(toolName)
	}
	return terminal.Cyan(terminal.SymbolStart), terminal.BoldCyan(toolName)
}

// coloredArgs renders a short summary of tool args for the start line with
// the parameter name colored separately from its value so dense tool calls
// (run_native_scan modules=[…] scanning_strategy=deep targets=[…]) stay readable:
// keys are tinted teal, values blue, and the `=` separator muted. Long
// values are clipped so the line stays readable on long runs.
func coloredArgs(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	sep := terminal.Muted("=")
	parts := make([]string, 0, len(args))
	for k, v := range args {
		val := strings.ReplaceAll(fmt.Sprintf("%v", v), "\n", " ")
		if len(val) > 80 {
			val = val[:77] + "…"
		}
		parts = append(parts, terminal.HiTeal(k)+sep+terminal.HiBlue(val))
	}
	return strings.Join(parts, " ")
}

// summarizeErr collapses a tool-result error payload into a single short
// line — multi-line stack traces from `bash` failures, JSON error bodies
// from web_fetch, etc. all reduce to the first non-empty line capped at
// ~120 characters.
func summarizeErr(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "error"
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if len(s) > 120 {
		s = s[:117] + "…"
	}
	return s
}

// CompactThinking trims each line of a reasoning stream and drops every blank
// line. "Blank" means empty after stripping Unicode whitespace, so tabs,
// non-breaking spaces, and other IsSpace padding all collapse. Paragraph
// breaks are intentionally not preserved: the thinking lane is faint status
// text, and GPT-5 / Codex reasoning summaries in particular embed long runs of
// newlines between a `**Title**` and its body that would otherwise blow the
// block up into dead space. Returns "" when nothing survives. Shared by the
// olium TUI's thinking block and the toollog reasoning lane so both compact
// reasoning identically.
func CompactThinking(s string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return strings.Join(out, "\n")
}

// indentLines prefixes every line of s with prefix. Used to inset the
// reasoning body under its `⋈ thinking` header.
func indentLines(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

// formatElapsed picks a unit appropriate to magnitude: ms below 1s, "1.2s"
// below 10s, whole seconds below 1m, "1m23s" above. Keeps the timing
// suffix narrow so it doesn't visually dominate the result line.
func formatElapsed(d time.Duration) string {
	if d <= 0 {
		return "0ms"
	}
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	if d < 10*time.Second {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Round(time.Second).Seconds()))
	}
	mins := int(d / time.Minute)
	secs := int((d % time.Minute) / time.Second)
	return fmt.Sprintf("%dm%ds", mins, secs)
}
