package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/internal/scratch"
)

// Input spooling: a path flag that names something other than a regular file —
// a shell process substitution (`-T <(printf 'https://host\n')` is /dev/fd/63),
// a named pipe, /dev/stdin — is copied once into a scratch file, and the flag is
// rewritten to name the copy.
//
// Every reader downstream assumes it can open a path more than once. The -T
// reader sniffs the file for a Burp scope export and then scans it for lines;
// the -i reader detects the format and then hands the path to a FileSource; a
// resume manifest records the path for a later process; a -P child is handed
// it outright. A pipe answers the first open and is empty for every one after
// it, and a child process never inherits the descriptor at all. On macOS the
// failure is silent: stat on a FIFO reports the bytes buffered in it, so the
// sniff reads the pipe dry and the scan reports "contain no targets".
//
// Spooling at the boundary fixes every reader at once instead of teaching each
// one about pipes.

// spoolFlagNames are the flags whose values name files a command reads.
var spoolFlagNames = []string{"target-file", "input", "input-file", "raw-request-file"}

// maxSpoolBytes bounds one spooled input. A target list or a request export
// past it is not something a pipe should be carrying.
const maxSpoolBytes = 256 << 20

// spoolNonRegularInputs rewrites every path flag of cmd that names a
// non-regular file to a scratch copy of its content.
func spoolNonRegularInputs(cmd *cobra.Command) error {
	for _, name := range spoolFlagNames {
		f := cmd.Flags().Lookup(name)
		if f == nil || !f.Changed {
			continue
		}
		if err := spoolFlag(f); err != nil {
			return err
		}
	}
	return nil
}

// spoolFlag spools the value(s) of one flag. Slice flags are rewritten in
// place so their order and the other entries are untouched.
func spoolFlag(f *pflag.Flag) error {
	if sv, ok := f.Value.(pflag.SliceValue); ok {
		vals := sv.GetSlice()
		changed := false
		for i, v := range vals {
			spooled, err := spoolPath(f.Name, v)
			if err != nil {
				return err
			}
			if spooled != v {
				vals[i] = spooled
				changed = true
			}
		}
		if changed {
			return sv.Replace(vals)
		}
		return nil
	}
	if f.Value.Type() != "string" {
		return nil
	}
	v := f.Value.String()
	spooled, err := spoolPath(f.Name, v)
	if err != nil || spooled == v {
		return err
	}
	return f.Value.Set(spooled)
}

// spoolPath returns path unchanged unless it names an existing non-regular,
// non-directory file, in which case it returns a scratch copy of the content.
// A value that is not a path at all — `-` for stdin, a URL, an inline request
// passed to -i — fails the stat and is returned as is.
func spoolPath(flagName, path string) (string, error) {
	if path == "" || path == "-" {
		return path, nil
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().IsRegular() || info.IsDir() {
		return path, nil
	}
	return spoolReader(flagName, path)
}

func spoolReader(flagName, path string) (string, error) {
	src, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("--%s %s: %w", flagName, path, err)
	}
	defer func() { _ = src.Close() }()

	dst, err := scratch.CreateTemp("input-spool-*" + filepath.Ext(path))
	if err != nil {
		return "", fmt.Errorf("--%s %s: spool to a temporary file: %w", flagName, path, err)
	}
	n, copyErr := io.Copy(dst, io.LimitReader(src, maxSpoolBytes+1))
	closeErr := dst.Close()
	switch {
	case copyErr != nil:
		_ = os.Remove(dst.Name())
		return "", fmt.Errorf("--%s %s: read: %w", flagName, path, copyErr)
	case closeErr != nil:
		_ = os.Remove(dst.Name())
		return "", fmt.Errorf("--%s %s: spool: %w", flagName, path, closeErr)
	case n > maxSpoolBytes:
		_ = os.Remove(dst.Name())
		return "", usageErrorf("--%s %s: a piped input is limited to %d MiB; write it to a file and pass that path",
			flagName, path, maxSpoolBytes>>20)
	}
	return dst.Name(), nil
}
