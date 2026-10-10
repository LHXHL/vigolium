package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/types"
)

// normalizeDiscoveryExtensions trims, de-dots and de-duplicates extension
// values ("php", ".php", " .bak " → php, bak). Discovery appends ".<ext>" to a
// name itself, so a leading dot would double it; ffuf users write the dot.
func normalizeDiscoveryExtensions(values []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			ext := strings.TrimLeft(strings.TrimSpace(part), ".")
			if ext == "" || seen[ext] {
				continue
			}
			seen[ext] = true
			out = append(out, ext)
		}
	}
	return out
}

// applyDiscoveryFlagOverrides applies --discovery-extensions and
// --discovery-max-depth to the discovery config. Only typed flags apply, so a
// config file's values stand otherwise.
//
// An explicit extension list is swept on every wordlist name directly: the
// confirm-before-fuzzing gate exists to keep vigolium from guessing a stack,
// and an operator naming the extensions has already made that call (ffuf -e
// semantics).
func applyDiscoveryFlagOverrides(cmd *cobra.Command, dc *config.DiscoveryConfig, opts *types.Options) error {
	if cmd.Flags().Changed("discovery-extensions") {
		exts := normalizeDiscoveryExtensions(opts.DiscoveryExtensions)
		if len(exts) == 0 {
			return usageErrorf("--discovery-extensions: no extensions given (want e.g. php,bak)")
		}
		opts.DiscoveryExtensions = exts
		confirm := false
		dc.Extensions.TestCustom = true
		dc.Extensions.CustomList = exts
		dc.Extensions.ConfirmRequired = &confirm
	}
	if cmd.Flags().Changed("discovery-max-depth") {
		depth := opts.DiscoveryMaxDepth
		if depth < 0 {
			return usageErrorf("--discovery-max-depth must be >= 0 (0 turns recursion off), got %d", depth)
		}
		dc.Recursion.Enabled = depth > 0
		if depth > 0 {
			dc.Recursion.MaxDepth = depth
		}
	}
	return nil
}

// applyKnownIssueScanTemplateFlags applies the repeatable
// --known-issue-scan-templates-dir and --known-issue-scan-templates. The first
// directory becomes templates_dir (the root a relative template resolves
// against, and the clone-avoidance pin); once more than one directory or any
// single template is named, the named set is exactly what runs.
func applyKnownIssueScanTemplateFlags(cmd *cobra.Command, kc *config.KnownIssueScanConfig, opts *types.Options) {
	dirs := opts.KnownIssueScanTemplatesDirs
	files := opts.KnownIssueScanTemplates
	if cmd.Flags().Changed("known-issue-scan-templates-dir") && len(dirs) > 0 {
		kc.TemplatesDir = dirs[0]
	}
	if len(files) > 0 || len(dirs) > 1 {
		kc.Templates = append(append([]string(nil), dirs...), files...)
	}
}
