package configcmd

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/terminal"
)

func newLsCmd(deps Deps, example string) *cobra.Command {
	var showSecrets bool
	cmd := &cobra.Command{
		Use:     "ls [filter]",
		Aliases: []string{"list", "view"},
		Short:   "Display current configuration",
		Long:    "Display current configuration settings. Sensitive values (API keys, tokens, credentials) are redacted by default; pass --show-secrets to reveal them in plaintext. Optionally filter by key (substring or fuzzy subsequence match, e.g. \"store\" matches \"storage.*\"). Filters containing glob metacharacters (* ? [ ]) are matched as glob patterns against the full key or any dot-segment, e.g. \"kno*\" matches \"known_issue_scan.*\".",
		Example: example,
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigLs(deps, args, showSecrets)
		},
	}
	cmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "Reveal sensitive values (API keys, tokens, credentials) in plaintext instead of [redacted]; prints a warning to stderr")
	return cmd
}

// configEntryView is one setting in the shape a machine consumer reads.
//
// Value is the REDACTED value under the default policy; Display is what the
// human table prints. `sensitive` is carried so a consumer can tell a genuinely
// empty setting from one that was withheld — an inference it would otherwise
// have to make by string-matching "[redacted]".
type configEntryView struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	Sensitive bool   `json:"sensitive"`
	Empty     bool   `json:"empty"`
	Redacted  bool   `json:"redacted"`
}

// display renders the value for the human table. It is derived rather than
// stored: "(empty)" is a rendering of Empty, and the redacted case already
// carries "[redacted]" in Value.
func (v configEntryView) display() string {
	if v.Empty {
		return "(empty)"
	}
	return v.Value
}

func newConfigEntryView(entry config.ConfigEntry, showSecrets bool) configEntryView {
	empty := entry.Value == "" || entry.Value == "<nil>"
	v := configEntryView{
		Key:       entry.Key,
		Value:     entry.Value,
		Sensitive: entry.Sensitive,
		Empty:     empty,
	}
	switch {
	case entry.Sensitive && !showSecrets && !empty:
		v.Value = clicommon.SecretPlaceholder
		v.Redacted = true
	case empty:
		v.Value = ""
	}
	return v
}

func runConfigLs(deps Deps, args []string, showSecrets bool) error {
	settings, err := config.LoadSettings(deps.ConfigFlag())
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	entries := config.FlattenSettings(settings)

	// Sort entries by key for stable output
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Key < entries[j].Key
	})

	// Apply filter if provided
	filter := ""
	if len(args) > 0 {
		filter = strings.ToLower(args[0])
	}

	// Secret reveal is gated exclusively on the purpose-specific --show-secrets
	// flag, never on the generic --force. This keeps API keys and tokens out of
	// agent transcripts and CI logs unless plaintext is explicitly requested.
	if showSecrets {
		fmt.Fprintf(os.Stderr, "%s Revealing sensitive configuration values in plaintext.\n", terminal.WarningSymbol())
	}

	matched := make([]configEntryView, 0, len(entries))
	for _, entry := range entries {
		if filter != "" && !keyMatches(strings.ToLower(entry.Key), filter) {
			continue
		}
		matched = append(matched, newConfigEntryView(entry, showSecrets))
	}

	// -j was accepted here and produced ANSI-colored prose on stdout with exit
	// 0 — the worst available combination, because a consumer parsing that
	// fails for a reason nothing in the exit status describes. The redaction
	// rule is identical in both modes: a machine caller is the LAST consumer
	// that should be handed plaintext credentials, since -j output routinely
	// lands in an agent transcript.
	if deps.jsonRequested() {
		return deps.WriteJSON("config ls", "entries", matched, len(matched), map[string]any{
			"config_path": config.ContractPath(clicommon.EffectiveConfigPath(deps.ConfigFlag())),
			"redacted":    !showSecrets,
			"filter":      filter,
		})
	}

	for _, e := range matched {
		fmt.Printf("%s = %s\n", sectionKeyColor(e.Key)(e.Key), colorizeValue(e.display()))
	}

	if count := len(matched); count == 0 {
		if filter != "" {
			fmt.Printf("%s No config keys matching %q\n", terminal.WarnPrefix(), filter)
		} else {
			fmt.Printf("%s No configuration found\n", terminal.WarnPrefix())
		}
		return nil
	}

	if filter == "" {
		fmt.Println()
		fmt.Printf("%s Config file: %s\n", terminal.InfoSymbol(), terminal.Gray(config.ContractPath(clicommon.EffectiveConfigPath(deps.ConfigFlag()))))
	}

	return nil
}

// keyMatches reports whether filter selects key. A filter containing glob
// metacharacters (* ? [ ]) is treated as a glob pattern; anything else falls
// back to the substring / fuzzy-subsequence match. A malformed glob pattern
// also falls back to fuzzy matching so a stray bracket never silently hides
// every key. Both inputs must already be lowercased.
func keyMatches(key, filter string) bool {
	if filter == "" {
		return true
	}
	if strings.ContainsAny(filter, "*?[") {
		if matched, err := globMatchKey(key, filter); err == nil {
			return matched
		}
	}
	return fuzzyMatchKey(key, filter)
}

// globMatchKey reports whether a path.Match-style glob pattern matches the full
// key or any single dot-segment. Keys never contain '/', so '*' matches any run
// of characters (including dots): "kno*" matches the key "known_issue_scan.x"
// directly and the segment "known_issue_scan" inside "scanning_pace.known_issue_scan.y".
// err is non-nil only when the pattern itself is malformed.
func globMatchKey(key, pattern string) (bool, error) {
	matched, err := path.Match(pattern, key)
	if err != nil {
		return false, err
	}
	if matched {
		return true, nil
	}
	for _, segment := range strings.Split(key, ".") {
		matched, err := path.Match(pattern, segment)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

// fuzzyMatchKey reports whether filter matches key as a substring, or as an
// in-order subsequence within any single dot-segment. Both inputs must already
// be lowercased. The per-segment subsequence rule lets "store" match
// "storage.*" (s-t-o-r-...-e inside the "storage" segment) while still
// rejecting unrelated keys whose s/t/o/r/e happen to be scattered across
// segments.
func fuzzyMatchKey(key, filter string) bool {
	if filter == "" {
		return true
	}
	if strings.Contains(key, filter) {
		return true
	}
	for _, segment := range strings.Split(key, ".") {
		if subsequenceMatch(segment, filter) {
			return true
		}
	}
	return false
}

func subsequenceMatch(s, filter string) bool {
	i := 0
	for j := 0; j < len(s) && i < len(filter); j++ {
		if s[j] == filter[i] {
			i++
		}
	}
	return i == len(filter)
}

// colorizeValue paints a config value based on its type so `config ls` output
// is easier to scan: redactions stand out in red, booleans/numbers/lists each
// get their own hue, and the placeholder "(empty)" is dimmed.
func colorizeValue(v string) string {
	switch {
	case v == clicommon.SecretPlaceholder:
		return terminal.BoldRed(v)
	case v == "(empty)":
		return terminal.Gray(v)
	case v == "true":
		return terminal.Green(v)
	case v == "false":
		return terminal.Red(v)
	case strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]"):
		return terminal.Magenta(v)
	}
	if _, err := strconv.ParseInt(v, 10, 64); err == nil {
		return terminal.Yellow(v)
	}
	if _, err := strconv.ParseFloat(v, 64); err == nil {
		return terminal.Yellow(v)
	}
	return terminal.HiWhite(v)
}

// sectionKeyColor returns a color function based on the top-level config section.
func sectionKeyColor(key string) func(string) string {
	section, _, _ := strings.Cut(key, ".")
	switch section {
	case "server":
		return terminal.Cyan
	case "database":
		return terminal.Blue
	case "notify":
		return terminal.Yellow
	case "dynamic-assessment":
		return terminal.Green
	case "mutation_strategy":
		return terminal.Teal
	case "scope":
		return terminal.HiGreen
	case "scanning_pace":
		return terminal.Magenta
	default:
		return terminal.Cyan
	}
}
