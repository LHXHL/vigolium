// Package apicontract holds the machine contract shared by every transport
// vigolium speaks to a program: the CLI's -j/--json documents and process exit
// status, and the REST API's error bodies.
//
// It is a leaf package on purpose. The CLI (pkg/cli and its subpackages) and the
// server (pkg/server) both need the same vocabulary, and neither may import the
// other; a value defined in one of them was a value the other had to copy, and a
// copied closed set is one that drifts. Nothing here may import another vigolium
// package.
package apicontract

// SchemaVersion is the contract version of every -j/--json envelope. A consumer
// gates on it; it is bumped on any breaking field change.
const SchemaVersion = 1

// Process exit codes. They are the CLI's half of the contract; REST reports an
// HTTP status instead and shares only the ErrorCode vocabulary.
//
//	0  success
//	1  error: the work failed; error.code says which way
//	2  usage error: bad flag, bad value, rejected combination
//	3  fuzz --fail-on-match / --fail-on-crack matched
//	4  --fail-on <severity> gate tripped
//	5  incomplete: the work ran but did not finish (timed_out, budget_exhausted, partial)
//
// 3, 4 and 5 are completed results rather than failures: the output was written
// before the code was chosen, and --soft-fail forces 0 for all of them.
const (
	ExitSuccess    = 0
	ExitError      = 1
	ExitUsageError = 2
	ExitFuzzMatch  = 3
	ExitFailOnGate = 4
	ExitIncomplete = 5
)
