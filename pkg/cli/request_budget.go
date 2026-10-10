package cli

import (
	"fmt"
	"strconv"

	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/types"
)

// requestCountValue is an int64 flag value that refuses negatives at parse
// time, so `--max-requests -1` is a usage error (exit 2) instead of a budget
// that refuses every request.
type requestCountValue struct{ target *int64 }

func (v requestCountValue) String() string {
	if v.target == nil {
		return "0"
	}
	return strconv.FormatInt(*v.target, 10)
}

func (v requestCountValue) Set(s string) error {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("must be a whole number of requests, got %q", s)
	}
	if n < 0 {
		return fmt.Errorf("must not be negative (0 = unlimited), got %d", n)
	}
	*v.target = n
	return nil
}

func (requestCountValue) Type() string { return "int" }

// registerRequestBudgetFlags declares --max-requests and
// --max-requests-per-host for the scan commands (scan, run via
// registerScanPipelineFlags; scan-url, scan-request via
// registerLightweightScanIOFlags). They bind into scanOpts; an untyped flag
// leaves scanning_pace.max_requests / max_requests_per_host in charge.
func registerRequestBudgetFlags(flags *pflag.FlagSet) {
	flags.Var(requestCountValue{&scanOpts.MaxRequests}, "max-requests",
		"Stop the scan after N requests to the targets (0 = unlimited). Exact for gated traffic; the browser crawl is held to it within 500ms; nuclei is not counted (see request_cap_enforcement on scan.started). A scan it stops is partial with stop_reason request_budget. Config: scanning_pace.max_requests")
	flags.Var(requestCountValue{&scanOpts.MaxRequestsPerHost}, "max-requests-per-host",
		"Send at most N requests to any one target host (0 = unlimited); further requests to that host fail fast and the phase records the host_request_budget limit. Config: scanning_pace.max_requests_per_host")
}

// applyRequestBudgetConfig fills the request budget from scanning_pace for a
// path that does not run runner.ApplyScanPace (scan-url / scan-request through
// the Runner): an untyped (zero) flag takes the config value.
func applyRequestBudgetConfig(settings *config.Settings, opts *types.Options) {
	if settings == nil || opts == nil {
		return
	}
	if opts.MaxRequests == 0 {
		opts.MaxRequests = settings.ScanningPace.MaxRequests
	}
	if opts.MaxRequestsPerHost == 0 {
		opts.MaxRequestsPerHost = settings.ScanningPace.MaxRequestsPerHost
	}
}

// directRequestBudget is the request budget of a direct scan-url /
// scan-request invocation, built once from the flags (the direct path loads no
// settings) and shared by every input of the invocation, so a batch is held to
// one budget. Nil when neither flag is set.
func directRequestBudget() *egress.Budget {
	return egress.NewBudget(scanOpts.MaxRequests, scanOpts.MaxRequestsPerHost)
}
