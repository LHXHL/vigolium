package clicommon

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/vigolium/vigolium/pkg/terminal"
)

// RunWithWatch had three framing problems, all of which only showed up once
// something other than a human was reading the output:
//
//  1. It ran fn() BEFORE validating the interval, so `--watch nonsense` executed
//     the query, printed a result, and only then reported that the interval was
//     unparseable. A validation error that arrives after the side effect is not
//     validation.
//  2. Between iterations it printed `\033[2J\033[H` and a "Refreshed at ..."
//     heading to stdout. Under --json that is terminal control bytes and prose
//     interleaved with the documents.
//  3. Under --json it emitted N top-level objects with no framing at all, so a
//     consumer doing one json.Unmarshal got a document followed by trailing
//     garbage.
//
// Repeating a query is a genuinely useful thing to do from a script, so the
// answer is not to forbid it: NDJSON is the shape a repeated machine read
// already has. One document per line, no clear-screen, no heading. The
// clear-screen behavior is kept for the human path, where it is the point, and
// is now conditional on stdout actually being a terminal.

// ErrWatchNotSupported marks a watch request the selected mode cannot honor.
var ErrWatchNotSupported = errors.New("--watch is not supported here")

// ErrWatchInterval marks an unparseable or non-positive --watch value. It is a
// sentinel rather than a message the caller string-matches: pkg/cli classifies
// both watch rejections as usage errors, and matching on a format string
// produced in another package is exactly the coupling the typed errors
// elsewhere in this package exist to avoid.
var ErrWatchInterval = errors.New("invalid --watch value")

// ParseWatchInterval parses a --watch value. Bare integers (e.g. "5") are
// treated as seconds; otherwise standard Go duration syntax is used (5s, 1m, 1h).
// An empty value yields a zero duration (watch disabled).
func ParseWatchInterval(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}
	// Bare integer → treat as seconds
	if n, err := strconv.Atoi(raw); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return time.ParseDuration(raw)
}

// WatchOptions describes how a repeated read should be framed.
type WatchOptions struct {
	// Raw is the --watch flag value.
	Raw string
	// JSON reports that the caller asked for machine output. A repeated read in
	// this mode is framed as NDJSON: fn writes one document per iteration and
	// nothing else goes to stdout.
	JSON bool
	// Mutates marks an operation that writes. Repeating a write on a timer is
	// never what --watch means, and the flag is rejected rather than obeyed.
	Mutates bool
}

// RunWithWatchOptions runs fn once, then repeats it every interval.
//
// Validation happens first, in full, before fn is called even once: an invalid
// interval or an unsupported mode must not produce a result it is about to
// reject.
func RunWithWatchOptions(opts WatchOptions, fn func() error) error {
	interval, err := ParseWatchInterval(opts.Raw)
	if err != nil {
		// ErrWatchInterval is what the caller classifies on; the parse error is
		// what tells the operator which character was wrong. Both are kept, with
		// the sentinel as the wrapped one since it is the branchable half.
		return fmt.Errorf("%w %q: %s", ErrWatchInterval, opts.Raw, err.Error())
	}
	if interval < 0 {
		return fmt.Errorf("%w %q: interval must be positive", ErrWatchInterval, opts.Raw)
	}
	if interval > 0 && opts.Mutates {
		return fmt.Errorf("%w: it repeats a read on a timer, and this command writes", ErrWatchNotSupported)
	}

	if err := fn(); err != nil {
		return err
	}
	if interval == 0 {
		return nil
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	for {
		select {
		case <-sigChan:
			// An interrupted watch has done exactly what it was asked to do:
			// every snapshot it printed is complete and valid.
			return nil
		case <-time.After(interval):
			printWatchSeparator(opts, interval)
			if err := fn(); err != nil {
				return err
			}
		}
	}
}

// printWatchSeparator emits the between-iteration decoration, and only where it
// belongs: never in JSON mode (where each iteration is one NDJSON document), and
// never when stdout is redirected (where the escape sequence lands in a file).
func printWatchSeparator(opts WatchOptions, interval time.Duration) {
	if opts.JSON {
		return
	}
	// terminal.IsTerminal rather than isatty directly: it is the house answer for
	// "is stdout a terminal" and honors terminal.SetIsTerminal, so this behavior
	// is reachable from a test.
	if !terminal.IsTerminal() {
		return
	}
	// Clear screen and move cursor to top-left.
	fmt.Print("\033[2J\033[H")
	fmt.Printf("%s Refreshed at %s (every %s, Ctrl+C to stop)\n\n",
		terminal.InfoSymbol(),
		terminal.Gray(time.Now().Format("15:04:05")),
		terminal.Cyan(interval.String()))
}
