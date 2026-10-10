package cli

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
)

// Finding lifecycle read filters: --verdict (status) and --new-since.
//
// --new-since takes either a time or a scan. A time (24h, 2d, a date, RFC3339)
// keeps findings first stored after it. A scan keeps findings first observed
// by a later scan and not observed by that one (finding_observations), which is
// the question "what did the scans after X find that X did not".

// parseVerdictList parses --verdict into lifecycle statuses, rejecting a name
// outside database.FindingStatuses.
func parseVerdictList(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		v := strings.ToLower(strings.TrimSpace(part))
		if v == "" {
			continue
		}
		if !database.IsValidFindingStatus(v) {
			return nil, usageErrorf("invalid --verdict %q (want one of: %s)", part, strings.Join(database.FindingStatuses, ", "))
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out, nil
}

// newSinceTime parses --new-since as a time, reporting ok=false when it is not
// one (and so names a scan).
func newSinceTime() (time.Time, bool) {
	raw := strings.TrimSpace(findingNewSince)
	if raw == "" {
		return time.Time{}, false
	}
	t, err := clicommon.ParseSince(raw)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// newSinceScanRef is the scan --new-since names, or "" when it is unset or a
// time.
func newSinceScanRef() string {
	raw := strings.TrimSpace(findingNewSince)
	if raw == "" {
		return ""
	}
	if _, isTime := newSinceTime(); isTime {
		return ""
	}
	return raw
}

// newSinceCreatedAfter is the time form of --new-since, or nil.
func newSinceCreatedAfter() *time.Time {
	if t, ok := newSinceTime(); ok {
		return &t
	}
	return nil
}

// newSinceExcludedStatuses is what --new-since leaves out: the dismissed
// verdicts, unless --include-dismissed or an explicit --verdict says otherwise.
// A "what is new" answer that includes findings someone already ruled out is
// noise an agent has to filter by hand every time.
func newSinceExcludedStatuses(verdicts []string) []string {
	if strings.TrimSpace(findingNewSince) == "" || findingIncludeDismissed || len(verdicts) > 0 {
		return nil
	}
	return database.DismissedFindingStatuses
}

// resolveNewSinceScan resolves the scan form of --new-since against the open
// store and sets filters.NewSince. A scan that does not exist in scope is an
// error (scan_not_found), never an empty result.
func resolveNewSinceScan(ctx context.Context, db *database.DB, filters *database.QueryFilters) error {
	ref := newSinceScanRef()
	if ref == "" {
		return nil
	}
	repo := database.NewRepository(db)
	scan, err := repo.ResolveScanRef(ctx, filters.ProjectUUID, ref)
	if err != nil {
		if errors.Is(err, database.ErrScanNotFound) {
			return clicommon.CodedErrorf(apicontract.CodeScanNotFound,
				"--new-since %q is neither a time (%s) nor a scan in scope: %w", ref, clicommon.TimeFilterSyntax, err)
		}
		return err
	}
	ns, err := repo.ResolveNewSince(ctx, scan)
	if err != nil {
		return err
	}
	filters.NewSince = ns
	return nil
}
