package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/pkg/terminal"
)

// Batch ingest: N specs in ONE process.
//
// Every `vigolium ingest` opens the same SQLite file for writing, and SQLite
// permits one writer at a time — so a consumer with 50 HAR files ran them
// serially, one subprocess each, and paid a full process start plus a database
// open per file. (Concurrency is now safe on its own: every open sets
// busy_timeout and journal_mode=WAL, and _txlock=immediate makes writers
// serialize rather than race. But a serialized writer is still a serialized
// writer, and N processes is the wrong shape regardless.)
//
// Repeating -i is the fix that removes the process fan-out entirely: one
// process, one database handle, one schema check, N sources ingested in order.
// --dir is the same thing for a directory a consumer already has on disk.
var (
	ingestDir     string
	ingestDirGlob string
)

func registerIngestBatchFlags(flags *pflag.FlagSet) {
	// -i itself stays a single string (registerInputSourceFlags owns it) so its
	// default of "-" for stdin keeps working; installIngestRepeatableInput makes
	// repeating it accumulate, which is the whole "N inputs, one process" story.
	flags.StringVar(&ingestDir, "dir", "",
		"Ingest every matching file in this directory in one process (pairs with -I to fix the format, and --dir-glob to narrow the match)")
	flags.StringVar(&ingestDirGlob, "dir-glob", "*",
		"Filename pattern for --dir (e.g. '*.har')")
}

// ingestTypedInputs records every -i value in the order typed. It is the
// authority when non-empty; ingestOpts.Input (the flag variable) only ever holds
// the LAST one, which is why the first would otherwise be lost.
var ingestTypedInputs []string

// installIngestRepeatableInput makes a repeated -i accumulate instead of
// overwriting.
//
// pflag binds one flag to one variable, and -i is a plain string: a second -i
// silently replaced the first, so `-i a.har -i b.har` ingested only b.har and
// reported success. Changing -i's type would break its "-" stdin default and
// every existing reader of globalInput, so the value is wrapped instead and each
// Set is recorded on the way past.
func installIngestRepeatableInput(cmd *cobra.Command) {
	f := cmd.Flags().Lookup("input")
	if f == nil {
		return
	}
	f.Value = &accumulatingString{inner: f.Value, seen: &ingestTypedInputs}
}

// accumulatingString wraps a string flag value so EVERY Set is remembered, while
// the flag itself keeps reporting the last value (which is what globalInput's
// existing readers expect).
type accumulatingString struct {
	inner pflag.Value
	seen  *[]string
}

func (a *accumulatingString) String() string { return a.inner.String() }
func (a *accumulatingString) Type() string   { return a.inner.Type() }
func (a *accumulatingString) Set(v string) error {
	if err := a.inner.Set(v); err != nil {
		return err
	}
	*a.seen = append(*a.seen, v)
	return nil
}

// ingestInputSources returns every input this invocation should ingest, in the
// order given: the -i values (first plus repetitions) then the --dir expansion.
// Duplicates collapse — the same file ingested twice is wasted work, and the
// upsert path makes it a no-op anyway.
func ingestInputSources(primary string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || p == "-" {
			return
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		if seen[abs] {
			return
		}
		seen[abs] = true
		out = append(out, p)
	}

	// The typed list is authoritative when present: it holds every -i in order,
	// where `primary` is only the last one pflag happened to store.
	if len(ingestTypedInputs) > 0 {
		for _, typed := range ingestTypedInputs {
			add(typed)
		}
	} else {
		add(primary)
	}

	if dir := strings.TrimSpace(ingestDir); dir != "" {
		matches, err := expandIngestDir(dir, ingestDirGlob)
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			add(m)
		}
	}
	return out, nil
}

// expandIngestDir lists the files in dir matching pattern, sorted.
//
// Sorted, and non-recursive: a deterministic order makes a re-run reproducible
// (record ids are assigned in ingest order), and walking subdirectories would
// silently widen what a caller pointed at — the difference between "this capture
// folder" and "everything under it" is exactly the kind of scope surprise this
// change is meant to avoid.
func expandIngestDir(dir, pattern string) ([]string, error) {
	if pattern == "" {
		pattern = "*"
	}
	// expandUserHome, like every other path/glob flag in this package: a quoted or
	// config-sourced --dir '~/captures' otherwise fails with a confusing
	// "no such file" instead of resolving.
	dir = expandUserHome(dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("--dir %q: %w", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ok, err := filepath.Match(pattern, e.Name())
		if err != nil {
			return nil, fmt.Errorf("--dir-glob %q: %w", pattern, err)
		}
		if ok {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	if len(out) == 0 {
		// An empty expansion is a hard error, not an empty run: a caller who
		// pointed at a directory expected files there, and reporting "ingested 0
		// records" for a typo'd path is indistinguishable from an empty capture.
		return nil, fmt.Errorf("--dir %q matched no files with --dir-glob %q", dir, pattern)
	}
	sort.Strings(out)
	return out, nil
}

// announceIngestBatch prints what the batch is about to do, so a multi-source
// run is legible in a log.
func announceIngestBatch(sources []string) {
	if len(sources) < 2 || globalSilent || globalJSON {
		return
	}
	fmt.Fprintf(os.Stderr, "%s ingesting %s source(s) in one process\n",
		terminal.InfoSymbol(), terminal.BoldCyan(fmt.Sprintf("%d", len(sources))))
}
