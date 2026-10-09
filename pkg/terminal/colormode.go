package terminal

import (
	"fmt"
	"os"
	"strings"
)

// ColorMode is the value of the CLI's global --color flag.
type ColorMode string

const (
	// ColorAuto colors only when a person is plausibly watching: stdout AND
	// stderr are both terminals, and no environment convention says otherwise.
	ColorAuto ColorMode = "auto"
	// ColorAlways colors unconditionally (the -P parent passes it to children
	// so their captured <output>.console.log reads like a live console).
	ColorAlways ColorMode = "always"
	// ColorNever never emits an escape sequence.
	ColorNever ColorMode = "never"
)

// ParseColorMode validates a --color value.
func ParseColorMode(s string) (ColorMode, error) {
	switch m := ColorMode(strings.ToLower(strings.TrimSpace(s))); m {
	case ColorAuto, ColorAlways, ColorNever:
		return m, nil
	case "":
		return ColorAuto, nil
	default:
		return "", fmt.Errorf("invalid --color %q: want auto, always or never", s)
	}
}

// colorEnv is the environment input to the color decision, captured once so
// the decision itself is a pure function a table test can drive.
type colorEnv struct {
	NoColor       string // NO_COLOR (https://no-color.org): any non-empty value disables
	ForceColor    string // FORCE_COLOR: non-empty forces color, except "0"/"false"
	CLIColorForce string // CLICOLOR_FORCE: non-empty and not "0" forces color
}

func colorEnvFromOS() colorEnv {
	return colorEnv{
		NoColor:       os.Getenv("NO_COLOR"),
		ForceColor:    os.Getenv("FORCE_COLOR"),
		CLIColorForce: os.Getenv("CLICOLOR_FORCE"),
	}
}

// colorDecision is the whole color policy.
//
// An explicit always/never is the operator's last word and beats every
// environment variable. Under auto the environment conventions apply — NO_COLOR
// first, because an opt-out that a force variable could silently undo is not an
// opt-out — and otherwise color requires BOTH streams to be terminals. A single
// switch cannot color stderr while keeping stdout plain, since a helper like
// BoldCyan does not know which stream its string is headed for, so "both" is
// the only rule under which a redirected stream never receives an escape code.
func colorDecision(mode ColorMode, stdoutTTY, stderrTTY bool, env colorEnv) bool {
	switch mode {
	case ColorAlways:
		return true
	case ColorNever:
		return false
	}
	if env.NoColor != "" {
		return false
	}
	if f := strings.ToLower(strings.TrimSpace(env.ForceColor)); f != "" {
		return f != "0" && f != "false"
	}
	if f := strings.TrimSpace(env.CLIColorForce); f != "" && f != "0" {
		return true
	}
	return stdoutTTY && stderrTTY
}

// ApplyColorMode sets the process-wide color state from the resolved --color
// mode. machine forces color off regardless of mode: -j, --events and
// --ci-output-format promise a predictable stream, and a driver capturing
// stderr alongside it should not have to strip escape codes from the notices.
func ApplyColorMode(mode ColorMode, machine bool) {
	if machine {
		SetColorEnabled(false)
		return
	}
	SetColorEnabled(colorDecision(mode, stdoutIsTerminal, stderrIsTerminal, colorEnvFromOS()))
}
