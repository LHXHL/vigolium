package cli

import (
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// interactiveAllowed is the fixed set of commands that may declare
// kindInteractive: their output is not a machine document at all. Anything
// else claiming the exemption fails the contract test.
var interactiveAllowed = map[string]string{
	"":                 "root: prints help",
	"help":             "cobra help",
	"kit":              "group: prints help",
	"kit oast":         "group: prints help",
	"agent olium":      "TUI",
	"olium":            "TUI",
	"server":           "long-running service",
	"arjun":            "passthrough shim",
	"ffuf":             "passthrough shim",
	"gau":              "passthrough shim",
	"katana":           "passthrough shim",
	"nuclei":           "passthrough shim",
	"skills gen-flags": "hidden dev generator",
}

// knownNonConforming is the ratchet: commands whose -j output does not yet match
// their declared kind, with what they do today. It may only shrink — B4/B5/B6/B7
// migrate these and delete the entry; B8 empties it. Adding an entry means a
// command regressed (or a new one shipped off-contract), which is what
// knownNonConformingCeiling stops.
var knownNonConforming = map[string]string{
	// Scans (B6: the single scan document).
	"scan":            "JSONL stream under -j",
	"run":             "JSONL stream under -j",
	"scan-url":        "bare scanResult (one target), envelope of scanResults (several), JSONL on the Runner path",
	"scan-request":    "same three shapes as scan-url",
	"agent autopilot": "raw summary map; nothing when repo is nil",
	"agent swarm":     "raw summary map; status hard-coded",
	"agent audit":     "raw summary map",
	"audit":           "raw summary map",

	// Agent (B7).
	"agent":         "--list-agents/--list-templates raw maps; --list-modes NDJSON passthrough",
	"agent query":   "raw agent.Result after streamed text",
	"agent session": "raw {sessions} or raw scan",
	"agent triage":  "text verdict",

	// Reads still RAW or NONE (B4).
	"auth lint":          "text report",
	"auth totp":          "raw {code,expires_in} always",
	"doctor":             "raw diagnostics report",
	"extensions eval":    "text",
	"extensions example": "text",
	"extensions lint":    "text report",
	"extensions preset":  "text",
	"extensions types":   "d.ts on stdout; raw {path,bytes} with -o",
	"js":                 "own --format json document",
	"kit harvest":        "raw kitHarvestResult",
	"kit js-beautify":    "raw kitBeautifyResult",
	"kit jwt-crack":      "raw kitJWTCrackResult",
	"kit oast new":       "raw",
	"kit oast poll":      "raw",
	"kit payload":        "raw anonymous structs",
	"kit secret-scan":    "raw kitSecretReport",
	"kit wordlist":       "raw (two shapes)",
	"log":                "`log <uuid>` prints a text transcript",
	"module":             "raw {modules,total,…} (module ls)",
	"module ls":          "raw {modules,total,…}",
	"project config":     "text",
	"project list":       "local --json flag, bare array",
	"skills":             "raw {skills,total} (skills list)",
	"skills get":         "raw SKILL.md markdown",
	"skills list":        "raw {skills,total}",
	"storage ls":         "local --json flag, bare array",
	"storage presign":    "local --json flag, bare object",
	"traffic":            "burp-glob save mode writes a raw aggregate",
	"version":            "raw map",

	// Mutations without the spine (B5).
	"auth load":       "text",
	"config clean":    "text",
	"config set":      "envelope without changed/action",
	"db clean":        "text",
	"db reset":        "text",
	"db seed":         "text",
	"finding load":    "raw {format,total,saved,skipped}",
	"import":          "raw map",
	"ingest":          "envelope without changed/action; remote target: raw {records_submitted,…}",
	"init":            "text",
	"kit tmp-clean":   "raw kitTmpCleanResult",
	"module disable":  "text",
	"module enable":   "text",
	"project create":  "text",
	"project delete":  "text",
	"project use":     "export line on stdout",
	"scope set":       "text",
	"skills install":  "text",
	"storage results": "text",
	"storage rm":      "text",
	"storage upload":  "text",
	"update":          "raw {steps}",

	// Streams that ignore -j (B4/B5).
	"db export":        "own --format stream; ignores -j",
	"export":           "own --format stream; ignores -j",
	"fuzz":             "raw summary; per-payload JSONL; local --pretty",
	"replay":           "raw replayOutput by default; ignores -j; local --pretty",
	"storage download": "raw object bytes",
}

// knownNonConformingCeiling pins the ratchet's size. Lower it when an entry is
// removed; never raise it.
const knownNonConformingCeiling = 68

// shadowCheckedFlags are the local flag names that must not shadow a persistent
// one: a local --json silently replaces the global -j on that command.
var shadowCheckedFlags = []string{"json", "pretty", "format"}

// preparedMachineTree returns the finished command tree with cobra's own
// commands in place, exactly as Execute builds it.
func preparedMachineTree(t *testing.T) *cobra.Command {
	t.Helper()
	rootCmd.InitDefaultHelpCmd()
	rootCmd.InitDefaultCompletionCmd()
	prepareCommandTree(rootCmd)
	return rootCmd
}

func isInteractiveAllowed(path string) bool {
	if _, ok := interactiveAllowed[path]; ok {
		return true
	}
	// cobra-generated families: `completion <shell>`, `__complete`, `__completeNoDesc`.
	return path == "completion" || strings.HasPrefix(path, "completion ") || strings.HasPrefix(path, "__complete")
}

// TestMachineContractCobraTree: every runnable command declares its -j kind,
// only the fixed list is exempt, no local flag shadows -j/--json, and the
// non-conforming ratchet only shrinks.
func TestMachineContractCobraTree(t *testing.T) {
	root := preparedMachineTree(t)

	runnable := map[string]*cobra.Command{}
	walkCommandTree(root, func(c *cobra.Command) {
		if c.Runnable() {
			runnable[commandPathWithoutRoot(c)] = c
		}
	})
	if len(runnable) < 80 {
		t.Fatalf("walked only %d runnable commands; the tree was not prepared", len(runnable))
	}

	for _, path := range sortedMapKeys(runnable) {
		c := runnable[path]
		kind, ok := c.Annotations[machineAnnotation]
		if !ok {
			t.Errorf("%q declares no machine kind: add it to machineKinds (machine_kinds.go)", path)
			continue
		}
		switch machineKind(kind) {
		case kindRead, kindMutation, kindScan, kindStream:
		case kindInteractive:
			if !isInteractiveAllowed(path) {
				t.Errorf("%q claims %q, which is reserved for help, TUIs, the server and shims", path, kind)
			}
		default:
			t.Errorf("%q declares unknown machine kind %q", path, kind)
		}
		if machineKind(kind) == kindInteractive {
			if _, listed := knownNonConforming[path]; listed {
				t.Errorf("%q is interactive and exempt; it does not belong in knownNonConforming", path)
			}
		}

		for _, name := range shadowCheckedFlags {
			f := c.LocalNonPersistentFlags().Lookup(name)
			if f == nil {
				continue
			}
			shadows := name == "json" || root.PersistentFlags().Lookup(name) != nil
			if !shadows {
				continue
			}
			if name == "format" && machineKind(kind) == kindStream {
				continue
			}
			if _, listed := knownNonConforming[path]; listed {
				continue
			}
			t.Errorf("%q defines a local --%s, which shadows the global flag; read the global instead", path, name)
		}
	}

	// The table and the ratchet name real commands only: a stale entry is a
	// declaration nobody checks.
	for path := range machineKinds {
		if _, ok := runnable[path]; !ok {
			t.Errorf("machineKinds declares %q, which is not a runnable command", path)
		}
	}
	for path := range knownNonConforming {
		if _, ok := runnable[path]; !ok {
			t.Errorf("knownNonConforming lists %q, which is not a runnable command", path)
		}
	}
	for path := range interactiveAllowed {
		if machineKinds[path] != kindInteractive {
			t.Errorf("interactiveAllowed lists %q, but machineKinds declares it %q", path, machineKinds[path])
		}
	}

	if n := len(knownNonConforming); n > knownNonConformingCeiling {
		t.Errorf("knownNonConforming has %d entries, over the ceiling of %d: the ratchet only shrinks — "+
			"make the new command emit its declared kind instead", n, knownNonConformingCeiling)
	} else if n < knownNonConformingCeiling {
		t.Errorf("knownNonConforming shrank to %d: lower knownNonConformingCeiling to %d so it cannot grow back", n, n)
	}
}

// TestEnvelopeKindFollowsDeclaration: a legacy newAgentEnvelope call, spelled
// with an alias or trailing flags, still renders its command's kind.
func TestEnvelopeKindFollowsDeclaration(t *testing.T) {
	preparedMachineTree(t)
	for command, want := range map[string]string{
		"db ls --list-tables": "read",
		"db stats":            "read",
		"traffic --group-by":  "read",
		"scan-url":            "scan",
		"config set":          "", // mutation without the spine: no kind until it has `changed`
		"no-such-command":     "",
	} {
		if got := newAgentEnvelope(command, "", nil, 0, 0, 0).Kind; got != want {
			t.Errorf("kind for %q = %q, want %q", command, got, want)
		}
	}
}

func sortedMapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
