package cli

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
)

// Reachability ("a dead target is loud"): a scan whose admitted target never
// answered exits 1 with error.code no_targets_reachable instead of "Native scan
// completed ... No findings." and exit 0. Re-exec'd like the scope tests
// (runA3), against local listeners only.

// a4ClosedURL is an http URL on a 127.0.0.1 port nothing listens on.
func a4ClosedURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	_ = l.Close()
	return "http://" + addr + "/"
}

// Direct path against a closed port: exit 1, the result says reachable:false
// with the refused class, no module ran, and the row stops with
// no_targets_reachable.
func TestScanURLDirectUnreachable(t *testing.T) {
	home := a3Home(t, "127.0.0.1")
	dbPath := filepath.Join(home, "a4.sqlite")
	dead := a4ClosedURL(t)

	code, stdout, stderr := runA3(t, home, "scan-url", dead, "-j", "--db", dbPath, "-m", "security-headers-missing")
	require.Equal(t, 1, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)

	doc := decodeOneScanDoc(t, stdout)
	assert.Equal(t, "failed", doc.Status)
	assert.Equal(t, database.ReasonNoTargetsReachable, doc.StopReason)
	assert.Zero(t, doc.Modules.Executed, "nothing executes against a dead target")
	assert.Positive(t, doc.Modules.Selected)
	require.Len(t, doc.Targets, 1)
	tgt := doc.Targets[0]
	require.NotNil(t, tgt.Reached)
	assert.False(t, *tgt.Reached)
	assert.Equal(t, scanDocReasonUnreachable, tgt.Reason)
	assert.Equal(t, "refused", tgt.Code)
	require.NotEmpty(t, doc.Errors)
	assert.Equal(t, apicontract.CodeNoTargetsReachable, doc.Errors[0].Code)
	assert.Contains(t, doc.Errors[0].Message, "refused")
	assert.True(t, strings.HasPrefix(tgt.ResolvedTarget, "http://127.0.0.1:"), tgt.ResolvedTarget)

	row, err := a3Repo(t, dbPath).GetScanByUUID(context.Background(), doc.ScanUUID)
	require.NoError(t, err)
	assert.Equal(t, "failed", row.Status)
	assert.Equal(t, database.ReasonNoTargetsReachable, row.StopReason)

	// Human mode: a red unreachable line, not the success banner.
	code, _, stderr = runA3(t, home, "scan-url", dead, "--db", dbPath, "-m", "security-headers-missing")
	require.Equal(t, 1, code, stderr)
	assert.Contains(t, stderr, "unreachable (connection refused)")
	assert.NotContains(t, stderr, "Native scan completed")
}

// A live target answers: reachable, and modules_run counts what executed (at
// most what was loaded).
func TestScanURLDirectReachableCountsExecutedModules(t *testing.T) {
	srv, _ := countingServer(t)
	home := a3Home(t, "127.0.0.1")
	code, stdout, stderr := runA3(t, home, "scan-url", srv.URL+"/", "-j", "--db", filepath.Join(home, "a4.sqlite"),
		"-m", "security-headers-missing")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)

	doc := decodeOneScanDoc(t, stdout)
	require.Len(t, doc.Targets, 1)
	require.NotNil(t, doc.Targets[0].Reached)
	assert.True(t, *doc.Targets[0].Reached)
	assert.Empty(t, doc.Targets[0].Reason)
	assert.Positive(t, doc.Modules.Executed)
	assert.LessOrEqual(t, doc.Modules.Executed, doc.Modules.Selected)
}

// A batch with one live and one dead input exits 0 and marks the dead one
// unreachable in targets[]; only a batch where nothing answered fails.
func TestScanURLDirectBatchUnreachable(t *testing.T) {
	srv, _ := countingServer(t)
	home := a3Home(t, "127.0.0.1")
	dbPath := filepath.Join(home, "a4.sqlite")
	dead := a4ClosedURL(t)

	code, stdout, stderr := runA3(t, home, "scan-url", "-t", srv.URL+"/", "-t", dead, "-j",
		"--db", dbPath, "-m", "security-headers-missing")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	doc := decodeOneScanDoc(t, stdout)
	require.Len(t, doc.Targets, 2)
	require.NotNil(t, doc.Targets[0].Reached)
	assert.True(t, *doc.Targets[0].Reached)
	require.NotNil(t, doc.Targets[1].Reached)
	assert.False(t, *doc.Targets[1].Reached)
	assert.Equal(t, dead, doc.Targets[1].Target)
	assert.Equal(t, "curtailed", doc.Status, "one input of two answered")
	assert.Contains(t, doc.Reasons, database.ReasonTargetsUnreachable)

	code, stdout, stderr = runA3(t, home, "scan-url", "-t", dead, "-t", a4ClosedURL(t), "-j",
		"--db", dbPath, "-m", "security-headers-missing")
	require.Equal(t, 1, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
}

// The runner path (scan -S, scan-url -S) preflights its targets: none answered
// is exit 1, the scan document's errors[0].code no_targets_reachable.
func TestRunnerScanUnreachableFails(t *testing.T) {
	dead := a4ClosedURL(t)
	cases := map[string][]string{
		"scan -S":     {"scan", "-t", dead, "-S", "-j"},
		"scan-url -S": {"scan-url", dead, "-S", "-j", "-m", "security-headers-missing"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			home := a3Home(t, "127.0.0.1")
			code, stdout, stderr := runA3(t, home, args...)
			require.Equal(t, 1, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
			assert.Equal(t, string(apicontract.CodeNoTargetsReachable), errorCode(t, stdout))
			assert.Contains(t, stdout, "connection refused", "the error says why")
		})
	}
}

func TestCodedScanErrorClassifiesNoTargetsReachable(t *testing.T) {
	err := codedScanError(&runner.TargetsUnreachableError{Unreachable: []database.TargetIssue{
		{Target: "http://a.test/", Code: "dns", Detail: "no such host"},
	}})
	assert.ErrorIs(t, err, runner.ErrNoTargetsReachable)
	assert.Equal(t, ExitError, classifyExitCode(err))
	assert.Equal(t, apicontract.CodeNoTargetsReachable, classifyErrorCode(err, ExitError))
	assert.Contains(t, err.Error(), "DNS lookup failed")
}

// directReach fails the invocation only when no input answered.
func TestDirectReachSettle(t *testing.T) {
	var none directReach
	assert.NoError(t, none.settle(nil), "nothing ran: nothing to report")

	var dead directReach
	dead.noteUnreachable(database.TargetIssue{Target: "http://a/", Code: "refused"}, "")
	err := dead.settle(nil)
	assert.True(t, errors.Is(err, runner.ErrNoTargetsReachable), "%v", err)

	var mixed directReach
	mixed.noteUnreachable(database.TargetIssue{Target: "http://a/", Code: "refused"}, "")
	mixed.noteReached()
	assert.NoError(t, mixed.settle(nil))

	boom := errors.New("boom")
	assert.Same(t, boom, dead.settle(boom), "an earlier error is kept")
}

// scan.finished carries targets_reached/targets_unreachable only when the
// preflight checked reachability.
func TestScanFinishedCarriesReachability(t *testing.T) {
	checked := &database.Scan{PhaseOutcomes: []database.PhaseOutcome{{
		Phase:   string(runner.PhasePreflight),
		Targets: &database.TargetTally{Requested: 3, Admitted: 3, Reached: 2, ReachabilityChecked: true},
	}}}
	var ev scanevents.Event
	applyScanCompletion(&ev, checked)
	require.NotNil(t, ev.TargetsReached)
	require.NotNil(t, ev.TargetsUnreachable)
	assert.Equal(t, 2, *ev.TargetsReached)
	assert.Equal(t, 1, *ev.TargetsUnreachable)

	unchecked := &database.Scan{PhaseOutcomes: []database.PhaseOutcome{{
		Phase:   string(runner.PhasePreflight),
		Targets: &database.TargetTally{Requested: 1, Admitted: 1},
	}}}
	ev = scanevents.Event{}
	applyScanCompletion(&ev, unchecked)
	assert.Nil(t, ev.TargetsReached, "--skip preflight: no reachability verdict")
	assert.Nil(t, ev.TargetsUnreachable)
}
