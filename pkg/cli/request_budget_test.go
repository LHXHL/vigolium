package cli

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
)

// The budget flags refuse negatives at parse time (a usage error), and bind
// into scanOpts.
func TestRequestBudgetFlags(t *testing.T) {
	saved := scanOpts.MaxRequests
	savedHost := scanOpts.MaxRequestsPerHost
	t.Cleanup(func() { scanOpts.MaxRequests, scanOpts.MaxRequestsPerHost = saved, savedHost })

	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	registerRequestBudgetFlags(fs)
	if err := fs.Parse([]string{"--max-requests", "250", "--max-requests-per-host", "20"}); err != nil {
		t.Fatal(err)
	}
	if scanOpts.MaxRequests != 250 || scanOpts.MaxRequestsPerHost != 20 {
		t.Fatalf("bound %d/%d", scanOpts.MaxRequests, scanOpts.MaxRequestsPerHost)
	}
	for _, bad := range []string{"-1", "lots"} {
		fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
		registerRequestBudgetFlags(fs)
		if err := fs.Parse([]string{"--max-requests", bad}); err == nil {
			t.Errorf("--max-requests %s parsed", bad)
		}
	}
}

// scan.finished lists every host any phase recorded as out of its per-host
// budget, deduplicated and sorted.
func TestApplyScanCompletion_BudgetExhaustedHosts(t *testing.T) {
	ev := scanevents.Event{Status: scanevents.StatusCompleted}
	applyScanCompletion(&ev, &database.Scan{PhaseOutcomes: []database.PhaseOutcome{
		{Phase: "discovery", State: database.PhaseCompleted, Limits: []string{database.LimitHostRequestBudget}, BudgetExhaustedHosts: []string{"b.test"}},
		{Phase: "dynamic-assessment", State: database.PhaseCompleted, Limits: []string{database.LimitHostRequestBudget}, BudgetExhaustedHosts: []string{"a.test", "b.test"}},
	}})
	if got := ev.BudgetExhaustedHosts; len(got) != 2 || got[0] != "a.test" || got[1] != "b.test" {
		t.Fatalf("budget_exhausted_hosts = %v", got)
	}
	if ev.Status != scanevents.StatusCompleted {
		t.Fatalf("a per-host limit changed the status to %s", ev.Status)
	}
}
