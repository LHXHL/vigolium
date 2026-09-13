package clicommon

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// --input-read-timeout was registered on scan, run, and ingest, documented as
// "Timeout for reading input from stdin or file", defaulted to 3m, and read by
// nothing. It was assigned into Options.InputReadTimeout and no consumer ever
// looked at that field, so the control was inert repo-wide:
//
//	( sleep 30 ) | vigolium scan --input-read-timeout 2s
//
// blocked for the full 30 seconds. Fourteen call sites reached for a bare
// io.ReadAll(os.Stdin), which has neither a deadline nor a size bound, so a
// producer that never closes its end hung the process forever with no way for
// the caller to bound it. For an agent driving vigolium from a shell tool that
// is unrecoverable: the tool call never returns.
//
// ReadBounded is the one reader. io.ReadAll cannot be cancelled once it is
// blocked in read(2), so the read runs on its own goroutine and the deadline is
// enforced by the caller side of a channel. The goroutine is left blocked on
// timeout rather than being forced to unwind: it holds only a buffer, the
// process is on its way to reporting the failure, and there is no portable way
// to interrupt a pending read on a pipe.

// DefaultStdinLimit bounds a single stdin read. It is deliberately generous —
// a HAR or a Burp export piped in can be large, and the deadline, not the size
// cap, is what protects against a producer that never finishes. The cap exists
// so a runaway or hostile producer cannot drive the process out of memory.
const DefaultStdinLimit = 512 << 20 // 512 MiB

// ErrStdinTimeout marks input that did not arrive within the deadline.
var ErrStdinTimeout = errors.New("timed out reading stdin")

// ErrStdinTooLarge marks input that exceeded the size bound.
var ErrStdinTooLarge = errors.New("stdin input exceeds the size limit")

type stdinResult struct {
	data []byte
	err  error
}

// ReadStdinBounded reads all of stdin subject to a size limit and a deadline.
//
// A zero or negative timeout means no deadline, preserving the previous
// behavior for callers that have not been given a timeout to honor. A zero or
// negative limit falls back to DefaultStdinLimit.
//
// On timeout it returns what the deadline is, not a generic I/O error: the
// caller is expected to surface --input-read-timeout as the dial that changes
// it, because "vigolium hung" is otherwise indistinguishable from "the producer
// is slow".
func ReadStdinBounded(limit int64, timeout time.Duration) ([]byte, error) {
	return ReadBounded(os.Stdin, "stdin", limit, timeout)
}

// ReadBounded applies the same bounds to an arbitrary reader, for the file
// branches that sit beside a stdin branch and should fail the same way.
//
// NOTE for a future caller: on timeout the read goroutine is left blocked. Every
// caller today is one-shot and on its way to reporting the failure and exiting,
// so the abandoned goroutine and its buffer live for microseconds. A long-lived
// caller that times out repeatedly would leak one goroutine per timeout.
func ReadBounded(r io.Reader, name string, limit int64, timeout time.Duration) ([]byte, error) {
	if limit <= 0 {
		limit = DefaultStdinLimit
	}

	done := make(chan stdinResult, 1)
	go func() {
		// Read one byte past the limit so exceeding it is detectable rather
		// than silently truncating the caller's input into a parse error.
		data, err := io.ReadAll(io.LimitReader(r, limit+1))
		done <- stdinResult{data: data, err: err}
	}()

	// A nil channel blocks forever, which is exactly what "no deadline" means —
	// so the select below covers both cases without a second copy of its first
	// arm.
	var deadline <-chan time.Time
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case res := <-done:
		if res.err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", name, res.err)
		}
		if int64(len(res.data)) > limit {
			return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrStdinTooLarge, name, limit)
		}
		return res.data, nil
	case <-deadline:
		return nil, fmt.Errorf("%w after %s: no complete input arrived on %s "+
			"(raise or disable the deadline with --input-read-timeout)",
			ErrStdinTimeout, timeout, name)
	}
}
