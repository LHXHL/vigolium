package cli

import (
	"io"
	"os"
)

// humanOut is where a mutating command's human report goes: stdout normally,
// stderr under -j, so stdout carries only the result document. For a command
// whose prose is the human result (a "Deleted N rows" line) but must not
// precede the -j document.
func humanOut() io.Writer {
	if globalJSON {
		return os.Stderr
	}
	return os.Stdout
}
