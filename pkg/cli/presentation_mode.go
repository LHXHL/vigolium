package cli

import (
	"io"
	"os"

	"github.com/spf13/pflag"
)

// Execute emits the structured error object only if globalJSON is set, and
// globalJSON is set by cobra's flag parsing. When parsing itself is what failed,
// it never ran — so the mode the caller asked for was unknown at exactly the
// moment it mattered most:
//
//	vigolium traffic --json --definitely-invalid   -> exit 2, one JSON usage_error
//	vigolium traffic --definitely-invalid --json   -> exit 2, EMPTY stdout
//
// Same two flags, same error, and whether the caller got a parseable answer
// depended on which one came first.
//
// resolvePresentationMode recovers the presentation flags from argv after a
// parse failure. It is deliberately NOT another hand-rolled argv scan of the
// kind that produced the banner bug: it is a real pflag.FlagSet that knows only
// the presentation flags, with unknown flags whitelisted. That means it honors
// --json=false, the -j shorthand, combined shorthands, the `--` terminator, and
// flag values, because pflag's own parser is doing the work.
//
// It is a best-effort recovery used only on the error path. With unknown flags
// whitelisted, pflag cannot know whether an unknown flag consumes the next
// argument, so an adversarial command line can still confuse it. Producing a
// structured error for the overwhelmingly common case beats producing nothing
// for half of them.
func resolvePresentationMode(args []string) {
	// Already resolved by a successful parse; nothing to recover.
	if machineOutputMode() {
		return
	}

	fs := pflag.NewFlagSet("presentation", pflag.ContinueOnError)
	fs.ParseErrorsAllowlist.UnknownFlags = true
	fs.SetOutput(io.Discard)
	// Usage must not print: this runs while an error is already being reported.
	fs.Usage = func() {}

	jsonOut := fs.BoolP("json", "j", false, "")
	silent := fs.Bool("silent", false, "")
	softFail := fs.Bool("soft-fail", false, "")
	ciFormat := fs.String("ci-output-format", "", "")

	// A parse error here is expected and ignored: the whole point is that argv
	// did not parse. Whatever the flagset did manage to bind is still better
	// than nothing.
	_ = fs.Parse(args)

	if *jsonOut {
		globalJSON = true
	}
	if *silent {
		globalSilent = true
	}
	if *softFail {
		globalSoftFail = true
	}
	if *ciFormat != "" {
		globalCIOutput = true
	}
}

// argsForPresentationRecovery returns the process arguments to re-scan.
func argsForPresentationRecovery() []string {
	if len(os.Args) < 2 {
		return nil
	}
	return os.Args[1:]
}
