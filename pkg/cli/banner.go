package cli

import (
	"fmt"
	"os"
	"sync"

	"github.com/spf13/cobra"
)

// The startup banner used to be printed by main() BEFORE cobra parsed anything,
// straight to stdout, gated on a raw scan of os.Args:
//
//	if !hasFlag("--json", "-j") && !hasFlag("--silent") && !isSubcommand(...)
//
// hasFlag compared whole arguments, so `--json=true` did not match. isSubcommand
// read only os.Args[1], so an alias (`tf`), a global before the command
// (`--db x traffic`), or a nested path (`db export`) did not match either. And
// the exclusion list named commands by hand, so every command whose stdout is
// data but which nobody remembered to list — `completion`, `js`, `storage
// download`, `kit`, `auth` — got a banner glued to the front of its output:
//
//	$ vigolium completion bash | head -1
//	:_/(o)\_: vigolium v0.4.6 - Crafted with <3 by @j3ssie
//	$ vigolium --json=true traffic --limit 1 | head -1
//	<-<(o)>-> vigolium v0.4.6 ...
//
// which makes `source <(vigolium completion bash)` execute the mascot and any
// JSON consumer fail to parse.
//
// The fix is not a better argv scan. It is that stdout ownership must not be
// decided from raw argv at all: the banner is presentation, it belongs on
// stderr, and it is emitted after cobra has resolved the command and its flags.
// On stderr the "which command" question stops being a correctness question —
// getting it wrong costs a cosmetic line, not a corrupt data stream.

// bannerOnce makes the banner at-most-once per process. It is what lets scan and
// import print THEIR banner — scan credits the discovery co-authors on a
// discovery-only run — as the first line of their configuration summary without
// the root hook having already printed a different one, and without either side
// needing to know about the other.
var bannerOnce sync.Once

// emitBanner writes one banner to stderr, the first time anyone asks. Every
// banner in the CLI goes through here: root's generic one, and the variants scan
// and import choose for themselves.
func emitBanner(banner string) {
	bannerOnce.Do(func() { fmt.Fprint(os.Stderr, banner) })
}

// printRootBanner writes the startup banner to stderr once per process.
//
// It is skipped in the modes that promise a clean stream (--json, --silent,
// --ci-output-format) — not because stdout would be corrupted (it is stderr
// now), but because those modes exist to make output predictable and a mascot
// in the log is noise a CI consumer did not ask for.
func printRootBanner(cmd *cobra.Command) {
	if machineOutputMode() || !commandWantsBanner(cmd) {
		return
	}
	emitBanner(GetBanner())
}

// bannerFreeCommands are the commands the ROOT hook does not banner, for two
// reasons that happen to want the same list:
//
//   - `help`, `completion`, `version`, and `config` answer one question and would
//     be noise (version prints its own identity line and would otherwise say it
//     twice; a run of `config set` calls prints one mascot per key set, which is
//     more banner than confirmation). Matching is by command name, so `project
//     config` loses its banner too — same reason, same kind of output.
//   - The scanning and import commands render a banner themselves, as the first
//     line of their configuration summary, and scan PICKS BETWEEN TWO of them —
//     it credits the discovery co-authors on a discovery-only run. Since the
//     root hook runs before RunE, letting it fire first would take that choice
//     away. (emitBanner's once-guard then makes the pair at-most-once whichever
//     order they occur in.)
//
// The list is cosmetic in both halves: since the banner moved to stderr, a name
// missing from it costs one extra line and nothing else. That is exactly why it
// is a list again rather than the cobra annotation it briefly was — the
// annotation cost a const, a nil-map init, a second lookup in the walk below,
// and a marker call from a hand-written five-name list in another file, to
// decide something that cannot corrupt anything.
var bannerFreeCommands = map[string]bool{
	"help":       true,
	"completion": true,
	"bash":       true,
	"zsh":        true,
	"fish":       true,
	"powershell": true,
	"version":    true,
	"config":     true,

	"scan":         true,
	"scan-url":     true,
	"scan-request": true,
	"run":          true,
	"import":       true,
	"olium":        true,
}

// commandWantsBanner reports whether cmd should get the root banner. It walks up
// the command tree, so `completion bash` is covered by `completion` and a future
// subcommand of a banner-free parent inherits the decision.
func commandWantsBanner(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		if bannerFreeCommands[c.Name()] {
			return false
		}
	}
	return true
}

// machineOutputMode reports that the caller asked for a predictable stream —
// -j/--json, --silent, or --ci-output-format. Four places had spelled this
// disjunction out by hand (two of them with the operands in a different order),
// which is three opportunities for the banner, the env-pin notice, the
// deprecation warning, and the error-path recovery to disagree about what
// "machine mode" means.
func machineOutputMode() bool {
	return globalJSON || globalSilent || globalCIOutput
}
