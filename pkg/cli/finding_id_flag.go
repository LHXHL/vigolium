package cli

import (
	"regexp"
	"strconv"
	"strings"
)

// `finding --id` takes the findings table's own autoincrement integer. It was
// registered as an IntVar, so a UUID reached pflag's parser and came back as:
//
//	invalid argument "3041e25d-…" for "--id" flag: strconv.ParseInt: parsing "3041e25d-…": invalid syntax
//
// That is accurate and useless. It names the Go function that failed, not the
// thing the caller got wrong — which is never a typo, but a wrong NAMESPACE:
// they are holding a UUID from somewhere (a stored HTTP record, an agent run, a
// finding id belonging to an entirely different tool) and reached for the only
// flag on this command that looked like an identifier.
//
// A transcript review of 26 recorded engagements found this exact move, and what
// it cost: the failed lookup was not repaired but WIDENED, into a search that
// matched 28 unrelated findings, and the identity the operator started with was
// never resolved at all. So the recovery has to be in the error, and the error
// has to name the flag that reads each namespace.
//
// Coercion was rejected as the alternative. Accepting a record UUID here and
// quietly resolving it to "the findings linked to that record" answers a
// question nobody asked with a result that looks like the one they wanted.

// findingIDRaw backs --id. It is a string so this file, rather than pflag, owns
// the parse and therefore the error text.
var findingIDRaw string

// uuidLike matches the canonical 8-4-4-4-12 hex shape. Deliberately shape-only:
// this decides which EXPLANATION to print, never whether an identifier exists,
// so a stricter version check would buy nothing and a looser one would call any
// hyphenated token a UUID.
var uuidLike = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// parseFindingID resolves --id into the integer filter, or explains why the
// value cannot be one. An empty value means the flag was not passed (0 = no
// filter), which is how the IntVar behaved.
func parseFindingID(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	if id, err := strconv.Atoi(raw); err == nil {
		if id < 0 {
			return 0, usageErrorf("--id must be a positive finding ID, got %d", id)
		}
		return id, nil
	}
	if uuidLike.MatchString(raw) {
		return 0, usageErrorf(
			"--id takes a finding's integer ID (e.g. --id 42), and %s is a UUID.\n\n"+
				"UUIDs in vigolium name different things, each with its own flag:\n"+
				"  a stored HTTP record      vigolium traffic --uuid %s\n"+
				"  an agent run's findings   vigolium finding --agentic-scan %s\n"+
				"  a native scan's findings  vigolium finding --scan-uuid %s\n\n"+
				"If it came from another tool, it is not a vigolium identifier: "+
				"find the finding by content instead (vigolium finding --search <term>), "+
				"and read the integer ID off that result.",
			raw, raw, raw, raw)
	}
	return 0, usageErrorf(
		"--id takes a finding's integer ID (e.g. --id 42), got %q.\n\n"+
			"To find one: vigolium finding -j --compact --fields id,severity,module_id,url",
		raw)
}
