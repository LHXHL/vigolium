package clicommon

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mattn/go-isatty"

	"github.com/vigolium/vigolium/pkg/terminal"
)

// Nine destructive commands each grew their own bufio.NewReader(os.Stdin)
// prompt. None checked for a terminal first, which produced three separate
// failure modes for a non-interactive caller:
//
//   - With stdin closed, the sites disagreed: some returned an error, one
//     discarded the read error and treated the empty line as a decline, and
//     several reported success for a delete that never happened.
//   - With stdin an open pipe that never closes, the prompt blocked forever. An
//     agent driving vigolium from a shell tool has no way out of that.
//   - With stdin carrying DATA rather than a human, the first line of that data
//     was consumed as the answer. A pipe beginning with "yes" authorized a
//     delete nobody approved.
//
// The prompts also went to stdout, so `--json db clean ...` wrote "Proceed?"
// into the caller's data channel and then waited on it.
//
// Confirm is the one implementation. It requires a terminal to read an answer;
// without one it refuses and names --force as the explicit authorization. A
// machine output mode is never treated as authorization on its own: a caller
// that wants the delete says so with --force, and one that did not is told which
// flag it is missing rather than having its data stream eaten.

// SecretPlaceholder is the literal that replaces a withheld credential in every
// rendering — `auth list`, `config ls`, `config set`'s echo. One const rather
// than five literals: consumers are told to recognize this exact string, and a
// drifting copy would silently stop being recognizable. (pkg/server has its own
// "<redacted>" for the REST surface; the two are deliberately separate
// contracts, but a change to either should consider the other.)
const SecretPlaceholder = "[redacted]"

// ErrConfirmationRequired marks a mutation that needs approval when no terminal
// is available to ask for it. Callers classify it as a usage error: the command
// line was incomplete, the work never started, and nothing changed.
var ErrConfirmationRequired = errors.New("confirmation required")

// ErrAborted marks an operator decline. It is not a failure: nothing changed,
// and the process should exit 0 having done exactly what was asked.
var ErrAborted = errors.New("aborted by operator")

// Confirm asks the operator to approve an irreversible action.
//
// action is a short phrase naming what will happen ("deleting 41 findings in
// project X"); it appears in both the prompt and the refusal, so a caller that
// hits the non-interactive path learns exactly what it would have authorized.
//
// Returns nil when approved, ErrAborted when declined, and an error wrapping
// ErrConfirmationRequired when there is no terminal to ask.
func Confirm(action string, force bool) error {
	if force {
		return nil
	}
	// stdin is the channel being read, so stdin is the channel that has to be a
	// terminal. Checking stdout instead would approve a run whose output is
	// redirected to a file but whose input is a data pipe, which is precisely
	// the case that silently consumed the caller's data.
	if !isatty.IsTerminal(os.Stdin.Fd()) && !isatty.IsCygwinTerminal(os.Stdin.Fd()) {
		return fmt.Errorf("%s requires confirmation, but stdin is not a terminal; "+
			"pass --force to authorize it non-interactively: %w", action, ErrConfirmationRequired)
	}

	// The prompt is an interactive artifact, not a result. It goes to stderr so
	// a redirected stdout stays exactly as clean as it is in every other mode.
	fmt.Fprintf(os.Stderr, "\n%s Proceed with %s? (type 'yes' to confirm): ",
		terminal.WarningSymbol(), action)

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}
	// EOF with no bytes is a decline, not an error: the operator closed the
	// prompt. EOF with bytes still counts as an answer.
	if strings.TrimSpace(strings.ToLower(response)) != "yes" {
		return ErrAborted
	}
	return nil
}

// HandleConfirmation runs Confirm and folds a decline into a clean exit, leaving
// only real errors to propagate. Callers do:
//
//	if done, err := clicommon.HandleConfirmation("deleting 41 findings", force); done {
//	    return err
//	}
func HandleConfirmation(action string, force bool) (done bool, err error) {
	switch confErr := Confirm(action, force); {
	case confErr == nil:
		return false, nil
	case errors.Is(confErr, ErrAborted):
		fmt.Fprintf(os.Stderr, "%s Aborted. Nothing was changed.\n", terminal.InfoSymbol())
		return true, nil
	default:
		return true, confErr
	}
}
