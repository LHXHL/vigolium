package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/notify/webhook"
	"github.com/vigolium/vigolium/pkg/types"
)

// webhookReceiver is a local endpoint recording every scan webhook POSTed to it.
type webhookReceiver struct {
	srv *httptest.Server
	mu  sync.Mutex
	got []webhook.ScanCompletedPayload
}

func (r *webhookReceiver) payloads(t *testing.T) []webhook.ScanCompletedPayload {
	t.Helper()
	// Drain is what the root runs before exit: everything fired is delivered
	// by the time it returns.
	require.Equal(t, 0, webhook.Drain(10*time.Second))
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]webhook.ScanCompletedPayload(nil), r.got...)
}

// webhookFixture starts a receiver and points --config at a file enabling the
// scan webhook (plus extra YAML, e.g. a scope), restoring globalConfig after.
func webhookFixture(t *testing.T, extraYAML string) *webhookReceiver {
	t.Helper()
	r := &webhookReceiver{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var p webhook.ScanCompletedPayload
		_ = json.NewDecoder(req.Body).Decode(&p)
		r.mu.Lock()
		r.got = append(r.got, p)
		r.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(r.srv.Close)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := fmt.Sprintf("%snotify:\n  enabled: true\n  provider: webhook\n  webhook:\n    url: %s\n    timeout_sec: 5\n%s", noOASTConfig, r.srv.URL, extraYAML)
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfg), 0o600))
	orig := globalConfig
	t.Cleanup(func() { globalConfig = orig })
	globalConfig = cfgPath
	return r
}

// scan-url, direct path: the row's completion fires scan.completed once the
// session closes, read from the row (completeness included).
func TestScanWebhookDirectCompleted(t *testing.T) {
	directRowFixture(t)
	recv := webhookFixture(t, "")
	srv := bareServer(t)
	in := directInput(t, srv.URL+"/")

	sess := newDirectScanSession(database.ScanNameScanURL, []scanInput{in})
	result, err := executeDirectScan(context.Background(), sess, in.rr, in.target, in.method)
	require.NoError(t, err)
	sess.close()

	got := recv.payloads(t)
	require.Len(t, got, 1)
	assert.Equal(t, webhook.EventScanCompleted, got[0].Event)
	assert.Equal(t, "completed", got[0].Status)
	assert.Equal(t, result.ScanUUID, got[0].ScanUUID)
	assert.Equal(t, "native", got[0].ScanType)
	assert.NotEmpty(t, got[0].Completeness)
}

// Interrupt (cancelled context): the cancelled row fires scan.cancelled.
func TestScanWebhookDirectInterrupted(t *testing.T) {
	directRowFixture(t)
	recv := webhookFixture(t, "")
	srv := bareServer(t)
	in := directInput(t, srv.URL+"/")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sess := newDirectScanSession(database.ScanNameScanURL, []scanInput{in})
	result, _ := executeDirectScan(ctx, sess, in.rr, in.target, in.method)
	require.NotNil(t, result)
	sess.close()

	got := recv.payloads(t)
	require.Len(t, got, 1)
	assert.Equal(t, webhook.EventScanCancelled, got[0].Event)
	assert.Equal(t, "cancelled", got[0].Status)
	assert.Equal(t, database.ReasonCancelled, got[0].StopReason)
}

// notify.webhook.events filters: a completed run with events [failed] posts
// nothing.
func TestScanWebhookEventsFilter(t *testing.T) {
	directRowFixture(t)
	recv := webhookFixture(t, "")
	cfg, err := os.ReadFile(globalConfig)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(globalConfig, append(cfg, []byte("    events: [failed]\n")...), 0o600))
	srv := bareServer(t)
	in := directInput(t, srv.URL+"/")

	sess := newDirectScanSession(database.ScanNameScanURL, []scanInput{in})
	_, err = executeDirectScan(context.Background(), sess, in.rr, in.target, in.method)
	require.NoError(t, err)
	sess.close()
	assert.Empty(t, recv.payloads(t))
}

// runnerWebhookFixture runs scan-url on the Runner path (-S), restoring the
// globals it sets.
func runnerWebhookFixture(t *testing.T) {
	t.Helper()
	directRowFixture(t)
	origStateless, origNoPassive := globalStateless, scanURLNoPassive
	t.Cleanup(func() { globalStateless, scanURLNoPassive = origStateless, origNoPassive })
	globalStateless = true
	globalDB = ""
	// Only the fixture's module: the webhook is under test, not the passive
	// registry (and several passive modules share a request's ordered-params
	// map, which -race flags).
	scanURLNoPassive = true
}

// scan-url -S (Runner path): the webhook reads the temp store's row before
// it is released.
func TestScanWebhookRunnerStateless(t *testing.T) {
	runnerWebhookFixture(t)
	recv := webhookFixture(t, "")
	srv := bareServer(t)
	in := directInput(t, srv.URL+"/")

	require.NoError(t, runRunnerScan(nil, in.rr, in.target))

	got := recv.payloads(t)
	require.Len(t, got, 1)
	assert.Equal(t, webhook.EventScanCompleted, got[0].Event)
	assert.Equal(t, in.target, got[0].Target)
	assert.NotEmpty(t, got[0].ScanUUID)
	assert.NotEmpty(t, got[0].Completeness)
}

// A run that fails (scope refuses the only target) fires scan.failed with the
// row's stop reason, from the same defer the success path uses.
func TestScanWebhookRunnerFailure(t *testing.T) {
	runnerWebhookFixture(t)
	recv := webhookFixture(t, "scope:\n  host:\n    include: [\"nothing-matches.invalid\"]\n")
	srv := bareServer(t)
	in := directInput(t, srv.URL+"/")

	err := runRunnerScan(nil, in.rr, in.target)
	require.Error(t, err)

	got := recv.payloads(t)
	require.Len(t, got, 1)
	assert.Equal(t, webhook.EventScanFailed, got[0].Event)
	assert.Equal(t, "failed", got[0].Status)
	assert.Equal(t, database.ReasonNoTargetsInScope, got[0].StopReason)
	assert.NotEmpty(t, got[0].Error)
}

// The fallback when no row exists: a failure before the runner created one
// still reports scan.failed; an export failure alone is not a failed scan.
func TestFireNativeScanWebhookFallback(t *testing.T) {
	directRowFixture(t)
	recv := webhookFixture(t, "")
	settings, err := loadProjectSettings(globalConfig)
	require.NoError(t, err)
	opts := &types.Options{ScanUUID: "no-row", ProjectUUID: "p1", Targets: []string{"https://t.example"}}

	fireNativeScanWebhook(settings, nil, opts, fmt.Errorf("session login failed"), false, time.Now())
	fireNativeScanWebhook(settings, nil, &types.Options{ScanUUID: "export-only"}, codedErrorf(apicontract.CodeExportFailed, "write %s: denied", "out.html"), false, time.Now())
	fireNativeScanWebhook(settings, nil, &types.Options{ScanUUID: "interrupted"}, nil, true, time.Now())

	byID := map[string]webhook.ScanCompletedPayload{}
	for _, p := range recv.payloads(t) {
		byID[p.ScanUUID] = p
	}
	require.Len(t, byID, 2)
	assert.Equal(t, webhook.EventScanFailed, byID["no-row"].Event)
	assert.Equal(t, "https://t.example", byID["no-row"].Target)
	assert.Equal(t, "session login failed", byID["no-row"].Error)
	assert.Equal(t, webhook.EventScanCancelled, byID["interrupted"].Event)
}

// `vigolium scan` (executeNativeScan): the defer registered after the database
// opened fires on success and on failure, reading the row of this pass — under
// --db and under -S, where the row lives in a temp store released afterwards.
func TestScanWebhookExecuteNativeScan(t *testing.T) {
	for _, tc := range []struct {
		name      string
		stateless bool
		scope     string
		event     string
	}{
		{"persisted success", false, "", webhook.EventScanCompleted},
		{"stateless success", true, "", webhook.EventScanCompleted},
		{"forced failure", false, "scope:\n  host:\n    include: [\"nothing-matches.invalid\"]\n", webhook.EventScanFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directRowFixture(t)
			recv := webhookFixture(t, tc.scope)
			srv := bareServer(t)

			origOpts := scanOpts
			t.Cleanup(func() { scanOpts = origOpts })
			scanOpts = types.DefaultOptions()
			scanOpts.Targets = []string{srv.URL + "/"}
			applyModuleSelection(scanOpts, true)
			scanOpts.Silent = true
			scanOpts.HeuristicsCheck = "none"
			scanOpts.Stateless = tc.stateless
			scanOpts.ConfigPath = globalConfig

			settings, err := loadProjectSettings(globalConfig)
			require.NoError(t, err)
			if !tc.stateless {
				settings.Database.Driver = "sqlite"
				settings.Database.SQLite.Path = globalDB
			}
			runErr := executeNativeScan(scanCmd, settings, "")
			if tc.event == webhook.EventScanFailed {
				require.Error(t, runErr)
			} else {
				require.NoError(t, runErr)
			}

			got := recv.payloads(t)
			require.Len(t, got, 1)
			assert.Equal(t, tc.event, got[0].Event)
			assert.Equal(t, scanOpts.ScanUUID, got[0].ScanUUID)
		})
	}
}
