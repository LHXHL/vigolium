package cli

import (
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

// readStdin is the cli-package binding of the shared bounded stdin reader. It
// supplies --input-read-timeout from the package global, which is what finally
// makes that flag do something: it was registered, documented, and read by
// nothing, so every stdin path in the CLI was an unbounded io.ReadAll that a
// producer could block forever.
//
// Commands that do not register --input-read-timeout still get the default
// deadline, because globalInputReadTimeout is initialized to it: zero now means
// "no deadline", and a command with no dial is exactly the one a caller cannot
// rescue.
//
// See pkg/cli/internal/clicommon/stdin.go for why the read runs on a goroutine.
func readStdin() ([]byte, error) {
	return clicommon.ReadStdinBounded(clicommon.DefaultStdinLimit, stdinReadTimeout())
}

// stdinReadTimeout resolves the effective deadline. It returns the global
// verbatim, including zero: ReadBounded treats a zero or negative timeout as
// "no deadline", which is what --input-read-timeout 0 has always been
// documented to mean.
//
// The previous version substituted the default whenever the global was <= 0, so
// `--input-read-timeout 0` silently re-armed the three-minute deadline it was
// asked to remove — the one value a caller passes precisely because their
// producer is slower than any deadline they can guess. The default now lives in
// the variable's initializer instead (see globalInputReadTimeout in root.go), so
// a command that never registers the flag is still bounded.
func stdinReadTimeout() time.Duration {
	return globalInputReadTimeout
}

// defaultInputReadTimeout matches the --input-read-timeout default registered in
// flag_helpers.go and the globalInputReadTimeout initializer. All three sides
// read this constant so they cannot drift.
const defaultInputReadTimeout = 3 * time.Minute

// inputReadTimeoutFlag is the flag name, shared by the registration helper and
// the negative-value check in PersistentPreRunE.
const inputReadTimeoutFlag = "input-read-timeout"

// validateInputReadTimeout rejects a negative --input-read-timeout. It reads the
// flag off the resolved command, so it is a no-op for the commands that don't
// register it, and it only fires when the flag was actually typed — the default
// can never be negative, and a Changed check keeps the error about the user's
// input rather than about the program's state.
func validateInputReadTimeout(cmd *cobra.Command) error {
	if cmd == nil {
		return nil
	}
	f := cmd.Flags().Lookup(inputReadTimeoutFlag)
	if f == nil || !f.Changed {
		return nil
	}
	if globalInputReadTimeout < 0 {
		return usageErrorf("--%s must be >= 0 (0 disables the deadline), got %s",
			inputReadTimeoutFlag, globalInputReadTimeout)
	}
	return nil
}

// resolveStdinInput decides whether a scan should drain stdin at all.
//
// stdinPiped comes from fileutil.HasStdin(), which reports true for ANY stdin
// that is not a character device. A pipe a parent process opened and never
// writes to counts: a CI runner, an agent harness, a supervisor, the read end
// left open by `vigolium ... | tee`. The scan's stdin peek then sat in
// readStdin() until that pipe closed or --input-read-timeout expired, so a run
// that already had every target it needed from -t/-T stalled for the full
// three-minute default before scanning anything.
//
// An explicit target source therefore wins over an inherited stdin. A TYPED
// `-i -` is a deliberate request for stdin and still wins over -t, so the
// documented "combine a pasted request with a target" invocation keeps working.
// inputTyped is load-bearing: -i defaults to "-", so testing inputValue alone
// would call every run an explicit stdin request and restore the stall.
// A typed `-i <file>` names the input source outright, so stdin is not it.
//
// explicit reports WHY stdin was chosen: true for a typed `-i -` (the operator
// asked for stdin, so a slow producer is legitimate and gets the full
// --input-read-timeout), false for the implicit "nothing else was given, maybe
// something is piped" guess, which readImplicitStdin bounds with a short
// first-byte window instead.
func resolveStdinInput(stdinPiped, inputTyped bool, inputValue string, targets, targetFiles int) (use, explicit bool) {
	if !stdinPiped {
		return false, false
	}
	if inputTyped {
		return inputValue == "-", inputValue == "-"
	}
	return targets == 0 && targetFiles == 0, false
}

// implicitStdinWait is how long an IMPLICIT stdin read waits for its first byte.
// fileutil.HasStdin is true for any non-terminal stdin, including a pipe a
// parent opened and never writes to, so a command that reads stdin only because
// nothing else was given used to sit for the whole --input-read-timeout (3m)
// and then fail with "no targets". Two seconds is long enough for `cat` or
// `echo` and short enough that an agent's tool call does not look hung. A
// producer that needs longer to emit its first line is served by a typed `-i -`,
// which waits the full deadline. A var only so tests can shorten it.
var implicitStdinWait = 2 * time.Second

// readImplicitStdin reads stdin that was chosen implicitly (see
// resolveStdinInput). It returns an error wrapping clicommon.ErrStdinNoData when
// nothing arrives within implicitStdinWait; after the first byte the normal
// --input-read-timeout applies.
func readImplicitStdin() ([]byte, error) {
	return clicommon.ReadBoundedWait(os.Stdin, "stdin", clicommon.DefaultStdinLimit,
		implicitStdinWait, stdinReadTimeout())
}

// readScanStdin reads stdin for a scan: the full deadline when it was asked for
// with a typed `-i -`, the first-byte window when it was only a guess.
func readScanStdin(explicit bool) ([]byte, error) {
	if explicit {
		return readStdin()
	}
	return readImplicitStdin()
}
