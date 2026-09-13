package cli

import (
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// seedTargetsFromTargetFiles promotes -T/--target-file lines into opts.Targets.
//
// A -T file's lines used to reach the scan ONLY as an input source (runner.New
// passes TargetsFilePaths to source.NewInputSource), leaving opts.Targets empty.
// Every phase that seeds itself from the CLI target list therefore saw zero
// targets and quietly did nothing: `run spidering -T hosts.txt` reported
// "completed - 0 records, 0 states, 0 actions in 0s", and Discovery degraded to
// ingest-only because deparos is gated on len(opts.Targets) > 0. The banner said
// "Targets: N" throughout, because formatTargetCounts reads the input source's
// total rather than the slice the phases use.
//
// This is the same promotion the stdin path already performs, so a piped list
// and a -T file now behave identically. TargetsFilePaths is cleared afterwards
// so NewInputSource builds one TargetSource instead of a TargetSource plus a
// FileSource over the same lines, which would ingest every URL twice.
//
// Only a target-LIST format is promoted, and which formats those are is
// source.IsTargetListFormat's answer, not a list kept here: -T with a spec or
// export -I (e.g. -I har) parses through that format's parser, whose records are
// not URLs a phase can seed from. A Burp scope file needs no special case — the
// FileSource content-sniffs it into the burpscope format and readTargetFileLines
// expands it to the same seed URLs, and burpscope is a target list in the
// registry.
func seedTargetsFromTargetFiles(opts *types.Options) error {
	if opts == nil || len(opts.TargetsFilePaths) == 0 {
		return nil
	}
	if !source.IsTargetListFormat(opts.InputFileMode) {
		return nil
	}

	lines, err := readTargetFilesLines(opts.TargetsFilePaths)
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		// Callers validate this up front (runNativeScan fails a target file that
		// yields nothing); leave the paths in place rather than silently turning
		// the run into a target-less DB scan.
		return nil
	}

	before := len(opts.Targets)
	opts.Targets = mergePositionalTargets(opts.Targets, lines)
	// Remembered so the fan-out hint can still tell whether this run was
	// file-driven after the paths are cleared: -P only fans out a -T file, and
	// suggesting it to a run that has none produces a command that degrades back
	// to a single serial scan with a warning.
	opts.TargetsSeededFromFile = true
	opts.TargetsFilePaths = nil

	zap.L().Info("seeded targets from target file(s)",
		zap.Int("from_file", len(lines)),
		zap.Int("cli_targets", before),
		zap.Int("total", len(opts.Targets)))
	return nil
}

// seedTargetsFromStdinLines promotes a piped URL list into opts.Targets, using
// the same trimming and `#` comment handling as a -T file so the two inputs
// accept the same list verbatim.
func seedTargetsFromStdinLines(opts *types.Options, content string) {
	opts.Targets = mergePositionalTargets(opts.Targets, targetLinesFrom(content))
}
