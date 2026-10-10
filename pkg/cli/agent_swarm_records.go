package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/database"
)

// expandProjectRecordsFromQuery returns every HTTP record UUID matching the
// given QueryFilters. ProjectUUID must already be set on filters by the caller.
func expandProjectRecordsFromQuery(ctx context.Context, repo *database.Repository, filters database.QueryFilters) ([]string, error) {
	if repo == nil {
		//vigolium:not-usage internal invariant
		return nil, fmt.Errorf("repository is required")
	}
	if filters.ProjectUUID == "" {
		//vigolium:not-usage internal invariant
		return nil, fmt.Errorf("project uuid is required")
	}
	qb := database.NewQueryBuilder(repo.DB(), filters)
	var uuids []string
	if err := qb.BuildRecordsQuery().Column("uuid").Scan(ctx, &uuids); err != nil {
		return nil, fmt.Errorf("failed to query http records: %w", err)
	}
	return uuids, nil
}

// parseRecordsFromSpec parses a comma-separated key=value spec into QueryFilters.
// Recognised keys: host, path, method, status, source, since, until.
//   - status: comma-or-space-separated integer list (within the value, e.g. "status=200|302")
//   - method: comma-or-space-separated method list (e.g. "method=GET|POST")
//   - since/until: the shared --from/--to grammar (relative offsets like "2d",
//     today/yesterday, YYYY-MM-DD, or RFC3339); an inverted window is an error
//
// Unknown keys produce an error rather than silently being ignored — typos
// shouldn't quietly degrade to a less-restrictive query.
func parseRecordsFromSpec(spec string, projectUUID string) (database.QueryFilters, error) {
	filters := database.QueryFilters{ProjectUUID: projectUUID}
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return filters, nil
	}
	// Collected rather than resolved inline so both bounds go through the shared
	// range helper below: a swarm that silently selects zero records reads as a
	// clean run, so an inverted window has to fail loudly here too.
	var since, until string
	for _, part := range splitSpecParts(spec) {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return filters, usageErrorf("invalid records-from entry %q: expected key=value", part)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if value == "" {
			return filters, usageErrorf("records-from key %q has no value", key)
		}
		switch key {
		case "host":
			filters.HostPattern = value
		case "path":
			filters.PathPattern = value
		case "method":
			filters.Methods = splitListValue(value)
		case "status":
			parts := splitListValue(value)
			codes := make([]int, 0, len(parts))
			for _, p := range parts {
				n, err := strconv.Atoi(p)
				if err != nil {
					return filters, fmt.Errorf("records-from status %q is not an integer", p)
				}
				codes = append(codes, n)
			}
			filters.StatusCodes = codes
		case "source":
			filters.Source = value
		case "since":
			since = value
		case "until":
			until = value
		default:
			return filters, fmt.Errorf("records-from key %q is not recognised (use: host, path, method, status, source, since, until)", key)
		}
	}

	// Labels are the spec keys, not flags — the caller already prefixes
	// "--records-from:", so repeating it here would stutter.
	dateFrom, dateTo, err := parseDateRangeFlags(since, until, "since=", "until=")
	if err != nil {
		return filters, err
	}
	filters.DateFrom, filters.DateTo = dateFrom, dateTo
	return filters, nil
}

// splitSpecParts splits a records-from spec on commas while keeping list-style
// values like "status=200|302" intact.
func splitSpecParts(spec string) []string {
	raw := strings.Split(spec, ",")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// splitListValue splits "a|b|c" or "a b c" into trimmed non-empty parts.
func splitListValue(v string) []string {
	v = strings.ReplaceAll(v, " ", "|")
	parts := strings.Split(v, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// dedupeStrings preserves order while removing duplicates.
func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
