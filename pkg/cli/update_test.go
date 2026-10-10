package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/selfupdate"
)

// --- auto-update gating ------------------------------------------------------

func TestAutoUpdateBlockedReasonMatrix(t *testing.T) {
	noEnv := func(string) string { return "" }
	base := autoUpdateEnv{command: "scan", stdoutTTY: true, stderrTTY: true, getenv: noEnv, exe: "/home/u/.local/bin/vigolium"}
	if r := autoUpdateBlockedReason(base); r != "" {
		t.Fatalf("a person at a terminal should be allowed, got %q", r)
	}

	envWith := func(name, value string) func(string) string {
		return func(k string) string {
			if k == name {
				return value
			}
			return ""
		}
	}
	cases := []struct {
		name    string
		mutate  func(e *autoUpdateEnv)
		blocked bool
	}{
		{"json", func(e *autoUpdateEnv) { e.jsonMode = true }, true},
		{"ci output format", func(e *autoUpdateEnv) { e.ciOutput = true }, true},
		{"events", func(e *autoUpdateEnv) { e.events = true }, true},
		{"stdout piped", func(e *autoUpdateEnv) { e.stdoutTTY = false }, true},
		{"stderr piped", func(e *autoUpdateEnv) { e.stderrTTY = false }, true},
		{"server", func(e *autoUpdateEnv) { e.command = "server" }, true},
		{"CI=true", func(e *autoUpdateEnv) { e.getenv = envWith("CI", "true") }, true},
		{"CI=woodpecker", func(e *autoUpdateEnv) { e.getenv = envWith("CI", "woodpecker") }, true},
		{"CI=false", func(e *autoUpdateEnv) { e.getenv = envWith("CI", "false") }, false},
		{"CI=0", func(e *autoUpdateEnv) { e.getenv = envWith("CI", "0") }, false},
		{"VIGOLIUM_AGENT", func(e *autoUpdateEnv) { e.getenv = envWith("VIGOLIUM_AGENT", "1") }, true},
		{"CLAUDECODE", func(e *autoUpdateEnv) { e.getenv = envWith("CLAUDECODE", "1") }, true},
		{"GITHUB_ACTIONS", func(e *autoUpdateEnv) { e.getenv = envWith("GITHUB_ACTIONS", "true") }, true},
		{"npm launcher binary", func(e *autoUpdateEnv) { e.exe = "/home/u/.vigolium/npm-bin/0.5.2/darwin-arm64/vigolium" }, true},
		{"homebrew binary", func(e *autoUpdateEnv) { e.exe = "/opt/homebrew/Cellar/vigolium/0.5.2/bin/vigolium" }, true},
		{"scan-url", func(e *autoUpdateEnv) { e.command = "scan-url" }, false},
		{"server-like name", func(e *autoUpdateEnv) { e.command = "serverless" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := base
			tc.mutate(&e)
			got := autoUpdateBlockedReason(e)
			if (got != "") != tc.blocked {
				t.Errorf("blocked=%q, want blocked=%v", got, tc.blocked)
			}
		})
	}
}

func TestCurrentAutoUpdateEnvSeesEventsFlag(t *testing.T) {
	cmd := machineTestCmd()
	cmd.Flags().String("events", "", "")
	if currentAutoUpdateEnv(cmd).events {
		t.Fatal("unset --events reported as set")
	}
	require.NoError(t, cmd.Flags().Set("events", "-"))
	if !currentAutoUpdateEnv(cmd).events {
		t.Fatal("--events not detected")
	}
}

func TestSelfManagedChannel(t *testing.T) {
	for path, want := range map[string]string{
		"/home/u/.vigolium/npm-bin/0.5.2/linux-x64/vigolium":                        "npm",
		"/usr/local/lib/node_modules/@vigolium/vigolium/vendor/linux-x64/vigolium":  "npm",
		"/opt/homebrew/Cellar/vigolium/0.5.2/bin/vigolium":                          "Homebrew",
		"/home/u/.local/bin/vigolium":                                               "",
		"/home/u/go/bin/vigolium":                                                   "",
		"/srv/npm-bin-tools/vigolium":                                               "",
		"/home/u/.vigolium/npm-bin/0.5.2/linux-x64/nested/too/deep/really/vigolium": "",
	} {
		if got := selfManagedChannel(path); got != want {
			t.Errorf("selfManagedChannel(%q) = %q, want %q", path, got, want)
		}
	}
}

// --- re-exec -----------------------------------------------------------------

type execCall struct {
	target string
	argv   []string
	env    []string
}

func stubExec(t *testing.T) *[]execCall {
	t.Helper()
	var calls []execCall
	prev := execReplaceFn
	execReplaceFn = func(target string, argv, env []string) error {
		calls = append(calls, execCall{target, argv, env})
		return errors.New("stubbed exec")
	}
	t.Cleanup(func() { execReplaceFn = prev })
	return &calls
}

func stubSelfUpdate(t *testing.T, res selfupdate.Result, err error) *[]selfupdate.Options {
	t.Helper()
	var seen []selfupdate.Options
	prev := selfUpdate
	selfUpdate = func(_ context.Context, o selfupdate.Options) (selfupdate.Result, error) {
		seen = append(seen, o)
		return res, err
	}
	t.Cleanup(func() { selfUpdate = prev })
	return &seen
}

func TestAutoUpdateReexecsReplacedPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writeUpdateCache("99.0.0") // fresh cache: npm says a newer release exists
	calls := stubExec(t)
	replaced := "/opt/tools/vigolium-real"
	seen := stubSelfUpdate(t, selfupdate.Result{From: "v0.1.0", To: "v99.0.0", Path: replaced, Changed: true, UpdateAvailable: true}, nil)

	runAutoUpdate("v0.1.0")

	require.Len(t, *seen, 1)
	assert.Equal(t, "v0.1.0", (*seen)[0].CurrentVersion)
	assert.Empty(t, (*seen)[0].InstallDir, "auto-update replaces the running binary, never ~/.local/bin")
	require.Len(t, *calls, 1, "re-exec after a successful update")
	assert.Equal(t, replaced, (*calls)[0].target, "re-exec targets the path that was replaced")
	assert.True(t, slices.Contains((*calls)[0].env, envAutoUpdateReexeced+"=1"), "loop guard set on the child")
}

func TestAutoUpdateNoReexecWithoutChange(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writeUpdateCache("99.0.0")
	calls := stubExec(t)

	stubSelfUpdate(t, selfupdate.Result{From: "v0.1.0", To: "v0.1.0", Path: "/x"}, nil)
	runAutoUpdate("v0.1.0")
	assert.Empty(t, *calls, "nothing replaced, nothing to re-exec")

	stubSelfUpdate(t, selfupdate.Result{}, errors.New("signature verification failed"))
	stderr := captureStderr(t, func() { runAutoUpdate("v0.1.0") })
	assert.Empty(t, *calls, "a failed update keeps the current process")
	assert.Contains(t, stderr, "auto-update failed")
}

// --- vigolium update -j ------------------------------------------------------

func withUpdateFlags(t *testing.T, check, dryRun, skipTemplates bool) {
	t.Helper()
	prev := []bool{updateSkipBinary, updateSkipTemplates, updateCheckOnly, updateDryRun}
	prevDir := updateInstallDir
	t.Cleanup(func() {
		updateSkipBinary, updateSkipTemplates, updateCheckOnly, updateDryRun = prev[0], prev[1], prev[2], prev[3]
		updateInstallDir = prevDir
	})
	updateSkipBinary, updateSkipTemplates, updateCheckOnly, updateDryRun = false, skipTemplates, check, dryRun
	updateInstallDir = ""
}

func runUpdateJSON(t *testing.T) (map[string]any, error) {
	t.Helper()
	withMachineDocumentState(t)
	globalJSON = true
	var err error
	out := captureStdout(t, func() { err = runUpdateCmd(updateCmd, nil) })
	docs := decodeStdoutDocuments(t, out)
	require.Len(t, docs, 1, "exactly one document")
	return docs[0], err
}

func TestUpdateCheckJSONEnvelope(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(packageManagerEnv, "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metadata.json" {
			t.Errorf("--check fetched %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"version":"v99.0.0"}`))
	}))
	defer srv.Close()
	t.Setenv(selfupdate.EnvBaseURL, srv.URL)
	withUpdateFlags(t, true, false, false)

	doc, err := runUpdateJSON(t)
	require.NoError(t, err)
	assert.Equal(t, "update", doc["command"])
	assert.Equal(t, "mutation", doc["kind"])
	assert.Equal(t, true, doc["ok"])
	assert.Equal(t, false, doc["changed"])
	assert.Equal(t, "check", doc["action"])
	assert.Equal(t, "v99.0.0", doc["to"])
	assert.Equal(t, true, doc["update_available"])
	items := doc["items"].([]any)
	require.Len(t, items, 2)
	assert.Equal(t, "available", items[0].(map[string]any)["status"])
	assert.Equal(t, "skipped", items[1].(map[string]any)["status"], "--check never touches templates")
}

func TestUpdateDryRunJSONEnvelope(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(packageManagerEnv, "")
	seen := stubSelfUpdate(t, selfupdate.Result{
		From: "v0.1.0", To: "v99.0.0", Path: "/opt/vigolium", UpdateAvailable: true, DryRun: true,
		Archive: "vigolium_99.0.0_linux_amd64.tar.gz", SHA256: strings.Repeat("a", 64),
	}, nil)
	withUpdateFlags(t, false, true, false)

	doc, err := runUpdateJSON(t)
	require.NoError(t, err)
	require.Len(t, *seen, 1)
	assert.True(t, (*seen)[0].DryRun)
	assert.Equal(t, false, doc["changed"])
	assert.Equal(t, true, doc["dry_run"])
	assert.Equal(t, "/opt/vigolium", doc["path"])
	items := doc["items"].([]any)
	assert.Equal(t, "planned", items[0].(map[string]any)["status"])
	assert.Equal(t, "planned", items[1].(map[string]any)["status"], "templates are not touched in a dry run")
}

func TestUpdateRefusesPackageManagedJSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(packageManagerEnv, "deb")
	seen := stubSelfUpdate(t, selfupdate.Result{}, nil)
	withUpdateFlags(t, false, false, true)

	doc, err := runUpdateJSON(t)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--skip-binary")
	assert.Empty(t, *seen, "a package-managed install never reaches the updater")
	items := doc["items"].([]any)
	assert.Equal(t, "failed", items[0].(map[string]any)["status"])
	assert.Equal(t, false, doc["changed"])
}

func TestUpdateFlagConflicts(t *testing.T) {
	withUpdateFlags(t, true, true, false)
	err := runUpdateCmd(updateCmd, nil)
	require.Error(t, err)
	assert.Equal(t, ExitUsageError, classifyExitCode(err))
}
