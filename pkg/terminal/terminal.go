package terminal

import (
	"fmt"
	"os"
	"strings"

	"github.com/mattn/go-runewidth"
	"golang.org/x/term"
)

// Notice prints a normal, prefixed console line to stderr (not a structured
// log). Format: "  ◆ [prefix] message". Color honors NO_COLOR / CI detection
// via the shared color helpers.
func Notice(prefix, message string) {
	fmt.Fprintf(os.Stderr, "  %s %s %s\n",
		Purple(SymbolInfo), BoldCyan("["+prefix+"]"), message)
}

// AgentNotice prints a prefixed console line to stderr like Notice but with the
// join / relation glyph (⋈). Used for autonomous engine decisions
// (e.g. discovery confirming an extension and queuing it for fuzzing).
func AgentNotice(prefix, message string) {
	fmt.Fprintf(os.Stderr, "  %s %s %s\n",
		Purple(SymbolBowtie), BoldCyan("["+prefix+"]"), message)
}

// NoticeArrow prints a prefixed console line to stderr like Notice but with the
// flow glyph (▷) instead of the info diamond (◆). Used for notices about
// requests/endpoints being carried forward into a later phase (e.g. jstangle
// recovering or preserving endpoints for dynamic assessment).
func NoticeArrow(prefix, message string) {
	fmt.Fprintf(os.Stderr, "  %s %s %s\n",
		Purple(SymbolArrow), BoldCyan("["+prefix+"]"), message)
}

// Global state for terminal capabilities
var (
	colorEnabled     = true
	ciMode           = false
	stdoutIsTerminal = false
	stderrIsTerminal = false
)

func init() {
	stdoutIsTerminal = term.IsTerminal(int(os.Stdout.Fd()))
	stderrIsTerminal = term.IsTerminal(int(os.Stderr.Fd()))
	// The library default is the CLI's --color=auto: color only when both
	// streams are terminals, with the NO_COLOR / FORCE_COLOR / CLICOLOR_FORCE
	// conventions applied. The CLI re-decides after parsing its flags
	// (ApplyColorMode).
	colorEnabled = colorDecision(ColorAuto, stdoutIsTerminal, stderrIsTerminal, colorEnvFromOS())
}

// IsTerminal reports whether stdout is an interactive terminal (TTY). It is
// false when stdout is redirected to a file or pipe — including the per-target
// .console.log capture used by `-P` parallel scans. Width-based truncation of
// live console lines keys off this so file/pipe output stays full-length and
// greppable instead of being clipped to the 150-column TerminalWidth fallback.
func IsTerminal() bool {
	return stdoutIsTerminal
}

// StderrIsTerminal reports whether stderr is an interactive terminal. The
// banner and other purely decorative stderr output key off it: a driver that
// captures stderr (2>log, 2>&1 | …) is not a person looking at a mascot.
func StderrIsTerminal() bool {
	return stderrIsTerminal
}

// SetStderrIsTerminal overrides the detected stderr TTY state, for tests.
func SetStderrIsTerminal(enabled bool) {
	stderrIsTerminal = enabled
}

// SetIsTerminal overrides the detected TTY state. Intended for tests and any
// caller that needs to force truncation behavior explicitly.
func SetIsTerminal(enabled bool) {
	stdoutIsTerminal = enabled
}

// TerminalWidth returns the current terminal width in columns.
// Falls back to 150 if detection fails (e.g. not a TTY, piped output).
func TerminalWidth() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 {
		return 150
	}
	return w
}

// IsColorEnabled returns whether color output is enabled
func IsColorEnabled() bool {
	return colorEnabled
}

// SetColorEnabled enables or disables color output
func SetColorEnabled(enabled bool) {
	colorEnabled = enabled
}

// SetCIMode enables CI mode (suppresses decorative output)
func SetCIMode(enabled bool) {
	ciMode = enabled
}

// IsCIMode returns whether CI mode is enabled
func IsCIMode() bool {
	return ciMode
}

// ShortenHome replaces the user's home directory prefix with "~" in a path.
func ShortenHome(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return path
	}
	if strings.HasPrefix(path, home) {
		return "~" + path[len(home):]
	}
	return path
}

// Truncate shortens s to at most maxWidth terminal columns, appending "…" when
// it had to cut. Width is measured in display cells (go-runewidth), so wide
// CJK/emoji characters count as two and a multibyte rune is never split.
func Truncate(s string, maxWidth int) string {
	if runewidth.StringWidth(s) <= maxWidth {
		return s
	}
	if maxWidth <= 1 {
		return "…"
	}
	return runewidth.Truncate(s, maxWidth, "…")
}

// HumanBytes formats a byte count for display, in binary units.
//
// It lives here because both the CLI's storage listing and the database stats
// report need it, and they sit on opposite sides of an import boundary — pkg/cli
// may import pkg/database but not the reverse, so a helper in either one is a
// helper the other has to copy.
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n2 := n / unit; n2 >= unit; n2 /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
