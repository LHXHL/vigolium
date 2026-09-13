package cli

import (
	"time"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

// readStdin is the cli-package binding of the shared bounded stdin reader. It
// supplies --input-read-timeout from the package global, which is what finally
// makes that flag do something: it was registered, documented, and read by
// nothing, so every stdin path in the CLI was an unbounded io.ReadAll that a
// producer could block forever.
//
// Commands that do not register --input-read-timeout still get the default
// deadline through globalInputReadTimeout, because the zero value there means
// "no deadline" and a command with no dial is exactly the one a caller cannot
// rescue.
//
// See pkg/cli/internal/clicommon/stdin.go for why the read runs on a goroutine.
func readStdin() ([]byte, error) {
	return clicommon.ReadStdinBounded(clicommon.DefaultStdinLimit, stdinReadTimeout())
}

// stdinReadTimeout resolves the effective deadline. The flag is only registered
// on the scanning and ingestion commands; everywhere else the global keeps its
// zero value, and falling back to the same documented default there means a
// `vigolium js` or `vigolium agent query` reading a pipe is bounded too.
func stdinReadTimeout() time.Duration {
	if globalInputReadTimeout > 0 {
		return globalInputReadTimeout
	}
	return defaultInputReadTimeout
}

// defaultInputReadTimeout matches the --input-read-timeout default registered in
// flag_helpers.go. Both sides read this constant so they cannot drift.
const defaultInputReadTimeout = 3 * time.Minute
