package cli

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/input/formats/burpscope"
	"github.com/vigolium/vigolium/pkg/input/formats/urls"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// runStatelessTargetFile iterates over each non-blank line in
// scanOpts.TargetsFilePaths, allocating an isolated temporary database per
// target and tearing it down before moving on. When --output is provided, the
// output path is suffixed with the target's hostname so per-target results do
// not overwrite each other. This is the --split-by-host path; without that flag
// runScanCmd instead runs a single shared pass over the whole target file for a
// unified output file.
func runStatelessTargetFile(cmd *cobra.Command, settings *config.Settings, strategyName string) error {
	targets, err := readTargetFilesLines(scanOpts.TargetsFilePaths)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("target file(s) %s contain no targets", strings.Join(scanOpts.TargetsFilePaths, ", "))
	}

	// Fan-out dispatch: any multi-target run routes through the fan-out, which
	// scans targets as isolated child processes and prints the compact
	// start/done progress lines plus a roll-up. With -P > 1 it runs several at a
	// time; at -P 1 the same path serializes (one worker slot) so a sequential
	// run gets the identical progress output — only the concurrency differs. A
	// single target keeps the in-process path below (live per-target console,
	// full banner) — there is nothing to fan out and no exec overhead.
	if len(targets) > 1 {
		return runStatelessTargetsParallel(cmd, settings, strategyName, targets)
	}

	if scanOpts.Resume && !scanOpts.Silent {
		fmt.Fprintf(os.Stderr, "%s --resume currently applies only to the parallel fan-out (-S -T --split-by-host -P>1); running a full sequential scan over all targets\n",
			terminal.WarnPrefix())
	}

	origTargets := append([]string(nil), scanOpts.Targets...)
	origFiles := scanOpts.TargetsFilePaths
	origOutput := scanOpts.Output
	origPrinted := scanOpts.ScanConfigPrinted
	origCaptured := scanOpts.CapturedConsole
	scanOpts.TargetsFilePaths = nil
	defer func() {
		scanOpts.Targets = origTargets
		scanOpts.TargetsFilePaths = origFiles
		scanOpts.Output = origOutput
		scanOpts.ScanConfigPrinted = origPrinted
		scanOpts.CapturedConsole = origCaptured
	}()

	// Per-target console capture: mirror each target's live console session to a
	// sibling <output>-<host>.console.log — the same artifact the -P parallel
	// fan-out writes for every child, so a sequential (non-P) split-by-host run is
	// no longer missing it. Only worthwhile when the requested output is deferred
	// to files (jsonl/html/sqlite/fs): with a plain console format the console IS
	// the output and a second copy would be redundant (and would nest with the
	// console-format transcript executeNativeScan starts itself). Skipped when
	// there's no live console to capture (silent, -j JSON, CI output). Setting
	// CapturedConsole makes each per-target run read like a console scan (findings
	// streamed in human-readable form, no repetitive "[status]" ticker), matching
	// what the -P children write; the terminal still sees everything live because
	// the capture passes bytes through to the real streams.
	captureConsole := !scanOpts.Silent && !globalJSON && !globalCIOutput && hasDeferredOutputFormat(scanOpts.OutputFormats)
	if captureConsole {
		scanOpts.CapturedConsole = true
	}

	multi := len(targets) > 1
	// Targets scope refused, folded so a batch whose every target was refused
	// fails like a single scan would (no_targets_in_scope) instead of exiting 0.
	var refused types.TargetAdmission
	for i, target := range targets {
		scanOpts.Targets = []string{target}
		// Force the scan summary banner to print per target.
		scanOpts.ScanConfigPrinted = false
		// This function is only reached on the --split-by-host path, so name each
		// output file by host. With a base path that's "<base>-<host>.<ext>"; with
		// no -o it's just "<host>.<ext>" (perTargetOutputPath handles the empty
		// base). A single target with a base keeps the literal -o (no host suffix).
		switch {
		case origOutput == "":
			scanOpts.Output = perTargetOutputPath("", target, i)
		case multi:
			scanOpts.Output = perTargetOutputPath(origOutput, target, i)
		default:
			scanOpts.Output = origOutput
		}

		if !scanOpts.Silent {
			fmt.Fprintf(os.Stderr, "\n%s %s %s\n",
				terminal.Purple(terminal.SymbolTarget),
				terminal.BoldHiBlue(fmt.Sprintf("[%d/%d]", i+1, len(targets))),
				terminal.HiCyan(target))
		}

		// Start the per-target console capture after the [i/N] header (a parent-loop
		// line, not part of the scan) so the log opens on the scan banner — the same
		// shape a -P child writes. Anchored to the resolved per-target output so it
		// lands next to the sqlite/html files as <output>-<host>.console.log.
		var (
			tc          *transcriptCapture
			consolePath string
		)
		if captureConsole {
			consolePath = perTargetConsolePath(scanOpts.Output)
			if c, terr := startTranscriptCapture(consolePath); terr != nil {
				fmt.Fprintf(os.Stderr, "%s Failed to capture console log to %s (%v); scanning without it\n",
					terminal.WarnPrefix(), terminal.Cyan(consolePath), terr)
				consolePath = ""
			} else {
				tc = c
			}
		}

		scanErr := executeNativeScan(cmd, settings, strategyName)

		// Restore the real streams before printing where the log landed, so that
		// note reaches the terminal instead of being swallowed into the log file.
		if tc != nil {
			tc.Stop()
		}
		if consolePath != "" && !scanOpts.Silent {
			fmt.Fprintf(os.Stderr, "%s Console log written to %s\n",
				terminal.InfoSymbol(), terminal.Cyan(consolePath))
		}

		var rejected *runner.TargetsRejectedError
		if errors.As(scanErr, &rejected) {
			refused.Rejected = append(refused.Rejected, rejected.Admission.Rejected...)
		}
		if scanErr != nil {
			zap.L().Error("Stateless target scan failed",
				zap.String("target", target),
				zap.Error(scanErr))
			fmt.Fprintf(os.Stderr, "%s scan for %s failed: %v\n",
				terminal.WarnPrefix(), terminal.HiCyan(target), scanErr)
			// Continue with remaining targets instead of aborting the batch.
		}
	}

	if len(refused.Rejected) == len(targets) {
		return noTargetsInScopeError(refused)
	}
	return nil
}

// hasDeferredOutputFormat reports whether formats requests any file-based output
// (jsonl/html/sqlite/fs) rather than only the live console. It's the signal that
// a captured <output>.console.log is worth writing: with a plain console format
// the console already IS the output.
func hasDeferredOutputFormat(formats []string) bool {
	for _, f := range formats {
		if f != "console" {
			return true
		}
	}
	return false
}

// readTargetFilesLines reads every target file in paths (each one URL/address
// per line) and concatenates their lines in order, preserving duplicates. It is
// the multi-file (`-T a -T b`) form of readTargetFileLines.
func readTargetFilesLines(paths []string) ([]string, error) {
	var lines []string
	for _, p := range paths {
		fileLines, err := readTargetFileLines(p)
		if err != nil {
			return nil, err
		}
		lines = append(lines, fileLines...)
	}
	return lines, nil
}

// targetFileLines memoizes the targets each -T file yielded. One invocation asks
// for the same file three times — the empty-file guard in runNativeScan, the
// banner's count, and the promotion into Options.Targets — and each parse is two
// full reads of the file (burpscope.SniffFile reads it whole, then the line
// scanner does), so caching the LINES rather than just the count is what keeps a
// large recon list to one pass. For a Burp scope export it also avoids
// re-expanding the include rules each time.
var (
	targetFileLinesMu sync.Mutex
	targetFileLines   = map[string][]string{}
)

// countTargetFileTargets returns the number of targets the given -T files
// contribute. It answers from the cache readTargetFileLines fills during flag
// validation and only falls back to reading when a caller reaches the banner
// first. A read failure reports what it has: the banner must never be the thing
// that fails a scan.
func countTargetFileTargets(paths []string) int {
	total := 0
	for _, p := range paths {
		lines, err := readTargetFileLines(p)
		if err != nil {
			continue
		}
		total += len(lines)
	}
	return total
}

// readTargetFileLines reads a target file (one URL or address per line),
// trimming whitespace and skipping blank lines and `#` comments. A Burp Suite
// scope export is expanded into the URLs its include rules describe instead —
// see expandBurpScopeTargets. Repeat calls for the same path are served from
// targetFileLines.
func readTargetFileLines(path string) ([]string, error) {
	targetFileLinesMu.Lock()
	cached, ok := targetFileLines[path]
	targetFileLinesMu.Unlock()
	if ok {
		return cached, nil
	}
	lines, err := parseTargetFileLines(path)
	if err != nil {
		return nil, err
	}
	targetFileLinesMu.Lock()
	targetFileLines[path] = lines
	targetFileLinesMu.Unlock()
	return lines, nil
}

// isTargetLine reports whether an already-trimmed line names a target, i.e. is
// neither blank nor a `#` comment. The -T file reader and the piped-stdin
// promotion both ask through here, so the two accept the same list verbatim —
// the contract seedTargetsFromStdinLines documents, with one rule behind it.
// (The file path stays on a bufio.Scanner rather than sharing targetLinesFrom:
// it streams, and its buffer cap is what keeps a very long URL line from
// silently truncating.)
func isTargetLine(line string) bool {
	return urls.IsTargetLine(line)
}

// targetLinesFrom splits target-list content into targets under isTargetLine.
func targetLinesFrom(content string) []string {
	var lines []string
	for _, line := range strings.Split(content, "\n") {
		if line = strings.TrimSpace(line); isTargetLine(line) {
			lines = append(lines, line)
		}
	}
	return lines
}

func parseTargetFileLines(path string) ([]string, error) {
	if burpscope.SniffFile(path) {
		return expandBurpScopeTargets(path)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open target file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); isTargetLine(line) {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read target file %q: %w", path, err)
	}
	return lines, nil
}

// perTargetOutputPath returns a target-specific variant of basePath so that
// per-target stateless exports do not clobber each other. The sanitized
// host[:port] is inserted before the format extension; if the target can't be
// parsed as a URL or yields an empty host, the iteration index is used.
func perTargetOutputPath(basePath, target string, idx int) string {
	stripped := types.StripFormatExtension(basePath)
	suffix := perTargetSuffix(target, idx)
	rest := strings.TrimPrefix(basePath, stripped)
	// No base path (e.g. --split-by-host without -o): the per-host file is named by
	// the host alone (<host><ext>), with no leading "-" separator to a base.
	if stripped == "" {
		return suffix + rest
	}
	return stripped + "-" + suffix + rest
}

// perTargetSuffix derives a filesystem-safe suffix from a target URL/host.
func perTargetSuffix(target string, idx int) string {
	candidate := target
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		candidate = u.Host
	}
	candidate = strings.NewReplacer(
		"/", "_", "\\", "_", ":", "_", "*", "_",
		"?", "_", "\"", "_", "<", "_", ">", "_", "|", "_", " ", "_",
	).Replace(candidate)
	candidate = strings.Trim(candidate, "._")
	if candidate == "" {
		return fmt.Sprintf("%03d", idx+1)
	}
	return candidate
}
