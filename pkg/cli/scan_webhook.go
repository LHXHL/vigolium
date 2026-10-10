package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/notify/webhook"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// webhookDrainTimeout bounds how long the process waits, on its way out, for
// the scan webhooks it fired to be delivered.
const webhookDrainTimeout = 10 * time.Second

// fireNativeScanWebhook posts the configured scan webhook for one runner pass
// (executeNativeScan, runRunnerScan). Every runner-backed entry point calls it
// from ONE defer registered right after its database opened, so it runs on
// every exit — success, curtailment, failure, interrupt — after the runner's
// finalizer wrote the terminal row and before the database is closed, a -S
// temp store is released, or a --db-isolate scratch is merged (the row read
// here is the authoritative copy at that moment).
//
// runErr and interrupted are only consulted when the row is missing or not
// terminal (a failure before the runner created it); an export failure is not
// a failed scan, so it is dropped here.
func fireNativeScanWebhook(settings *config.Settings, repo *database.Repository, opts *types.Options, runErr error, interrupted bool, startedAt time.Time) {
	if opts == nil || opts.ScanUUID == "" {
		return
	}
	if runErr != nil && isExportFailure(runErr) {
		runErr = nil
	}
	webhook.FireNativeScanOutcome(settings, repo, opts.ScanUUID, webhook.Outcome{
		Err:         runErr,
		Interrupted: interrupted,
		ProjectUUID: opts.ProjectUUID,
		Target:      strings.Join(opts.Targets, ", "),
		StartedAt:   startedAt,
	})
}

// drainScanWebhooks gives the webhooks this process fired a bounded chance to
// land before it exits. Called once from Execute, so every command that fired
// one gets it; the server is long-lived and does not need it. Undelivered
// POSTs are named on stderr (never stdout, which may carry a JSON document).
func drainScanWebhooks() {
	if n := webhook.Drain(webhookDrainTimeout); n > 0 {
		fmt.Fprintf(os.Stderr, "%s %d scan webhook(s) not delivered within %s; exiting without them\n",
			terminal.WarnPrefix(), n, webhookDrainTimeout)
	}
}
