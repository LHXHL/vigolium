package cli

import (
	"fmt"
	"os"

	"github.com/vigolium/vigolium/pkg/burpbridge"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// importLimitFor separates the LISTING limit from the IMPORT limit.
//
// One flag governed two unrelated things: -n/--limit is a display cap ("show me
// a page"), and the same value was carried through QueryFromFilters into the
// bridge query that --save-to-vigolium-db writes from. A default page size of
// 100 is a sensible listing; as an import bound it means the destination store
// silently holds the first 100 records of a host's history.
//
// Which of the two the operator meant is knowable: they typed -n, or they did
// not. An untyped -n is a listing default and must not bound a write, so the
// import runs unlimited. A typed -n is an explicit budget and is honored.
// limitTyped is whether -n/--limit actually appeared on the command line. Passed
// in rather than read from trafficCmd here: reaching for the command from a
// function its own RunE calls is a package initialization cycle (trafficCmd →
// runTraffic → here → trafficCmd), which Go rejects outright. The caller holds
// cmd, so it can just ask.
func importLimitFor(listingLimit int, limitTyped bool) int {
	if limitTyped {
		return listingLimit
	}
	return 0 // no LIMIT clause
}

// warnImportTruncated says loudly when an import stopped at its limit rather
// than at the end of the history. The alternative — reporting the same summary
// whether or not everything crossed — is what made the truncation silent.
func warnImportTruncated(result burpbridge.ImportResult, limit int) {
	if limit <= 0 || result.Matched <= int64(limit) {
		return
	}
	fmt.Fprintf(os.Stderr, "%s imported %s of %s matching record(s) — capped by %s. Pass %s (or raise %s) to import the rest.\n",
		terminal.WarnPrefix(),
		terminal.BoldYellow(fmt.Sprintf("%d", result.Selected)),
		terminal.BoldYellow(fmt.Sprintf("%d", result.Matched)),
		terminal.BoldCyan("-n/--limit"),
		terminal.BoldCyan("-a/--all"),
		terminal.BoldCyan("-n"))
}
