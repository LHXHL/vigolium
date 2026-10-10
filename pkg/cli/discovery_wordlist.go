package cli

import (
	"os"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
)

// normalizeDiscoveryWordlists validates the --discovery-wordlist values and
// returns the file list deparos streams, in order, without duplicates.
//
// The flag is repeatable. A single value holding commas is split only when
// every part names an existing file, so a comma-joined list from an older
// invocation keeps working while a path that contains a comma stays one path.
// Every resulting path must be an existing regular file: a typo fails the run
// with a usage error (exit 2) instead of silently scanning without the list.
func normalizeDiscoveryWordlists(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	var out []string
	seen := make(map[string]bool, len(values))
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, raw := range values {
		v := strings.TrimSpace(raw)
		if v == "" {
			return nil, usageErrorf("--discovery-wordlist: empty path")
		}
		if parts, ok := splitExistingWordlists(v); ok {
			for _, p := range parts {
				add(p)
			}
			continue
		}
		if err := checkWordlistFile(v); err != nil {
			return nil, err
		}
		add(v)
	}
	return out, nil
}

// splitExistingWordlists splits a comma-joined value into paths when it holds
// a comma and every non-empty part is an existing regular file.
func splitExistingWordlists(v string) ([]string, bool) {
	if !strings.Contains(v, ",") {
		return nil, false
	}
	var parts []string
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if info, err := os.Stat(config.ExpandPath(part)); err != nil || !info.Mode().IsRegular() {
			return nil, false
		}
		parts = append(parts, part)
	}
	return parts, len(parts) > 0
}

func checkWordlistFile(p string) error {
	info, err := os.Stat(config.ExpandPath(p))
	if err != nil {
		if os.IsNotExist(err) {
			return usageErrorf("--discovery-wordlist %q: no such file", p)
		}
		return usageErrorf("--discovery-wordlist %q: %v", p, err)
	}
	if !info.Mode().IsRegular() {
		return usageErrorf("--discovery-wordlist %q: not a regular file", p)
	}
	return nil
}
