package exttest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func caseByName(t *testing.T, r *Report, ext, name string) CaseResult {
	t.Helper()
	for _, c := range r.Cases {
		if c.Extension == ext && c.Case == name {
			return c
		}
	}
	t.Fatalf("no case %s/%s in %+v", ext, name, r.Cases)
	return CaseResult{}
}

func TestRunFixtures_PassingDir(t *testing.T) {
	r, err := RunFixtures(filepath.Join("testdata", "fixtures"), FixtureOptions{})
	require.NoError(t, err)

	for _, c := range r.Cases {
		if c.Status == StatusFail {
			t.Errorf("%s/%s failed: %v (errors %v)", c.Extension, c.Case, c.Failures, c.Errors)
		}
	}
	assert.Equal(t, 0, r.Failed)
	assert.Equal(t, 4, r.Passed)
	assert.Equal(t, 1, r.Skipped, "the hook is one skipped entry")

	admin := caseByName(t, r, "title_check.js", "admin")
	assert.Equal(t, "ext-title-check", admin.ModuleID)
	assert.Equal(t, 1, admin.Findings)

	reflected := caseByName(t, r, "reflect_probe.js", "reflected")
	assert.Equal(t, 1, reflected.MockRequests, "the probe reached the 127.0.0.1 mock")
	assert.Empty(t, reflected.UnmatchedRequests)
	assert.Zero(t, reflected.NetworkCallsBlocked)

	offline := caseByName(t, r, "reflect_probe.js", "offline")
	assert.EqualValues(t, 1, offline.NetworkCallsBlocked)
	require.Len(t, offline.Errors, 1)
	assert.Contains(t, offline.Errors[0].Message, NetworkDisabledMessage, "vigolium.http.send throws the offline error")
	assert.Equal(t, "URL_PARAM:q", offline.Errors[0].Insertion)

	hook := caseByName(t, r, "hook.js", "")
	assert.Equal(t, StatusSkip, hook.Status)
}

func TestRunFixtures_FailingCase(t *testing.T) {
	r, err := RunFixtures(filepath.Join("testdata", "failing"), FixtureOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, r.Failed)
	c := caseByName(t, r, "always.js", "quiet")
	assert.Equal(t, StatusFail, c.Status)
	require.NotEmpty(t, c.Failures)
	assert.Contains(t, c.Failures[0], "expected 0 finding(s), got 1")
	assert.Contains(t, c.Failures[0], "Always fires")
}

func TestRunFixtures_SingleFile(t *testing.T) {
	r, err := RunFixtures(filepath.Join("testdata", "fixtures", "title_check.js"), FixtureOptions{})
	require.NoError(t, err)
	assert.Equal(t, 2, r.Passed)
	assert.Len(t, r.Cases, 2)
}

func TestRunFixtures_OrphanAndMissingExpectation(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "ghost.fixtures"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.js"), []byte(`module.exports = {
  id: "a", name: "A", type: "passive", scanTypes: ["per_request"],
  scanPerRequest: function(ctx) { return null; }
};`), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "a.fixtures"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.fixtures", "x.http"),
		[]byte("GET / HTTP/1.1\nHost: a.example.com\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.fixtures", "typo.http"),
		[]byte("// expect: {\"finding\": 0}\nGET / HTTP/1.1\nHost: a.example.com\n"), 0o644))

	r, err := RunFixtures(dir, FixtureOptions{})
	require.NoError(t, err)
	assert.Equal(t, 3, r.Failed)
	assert.Contains(t, caseByName(t, r, "a.js", "x").Failures[0], "no expectation")
	assert.Contains(t, caseByName(t, r, "a.js", "typo").Failures[0], "unknown field")
	assert.Contains(t, caseByName(t, r, "ghost.fixtures", "").Failures[0], "no extension")
}

// TestBundledPresetFixtures runs `ext test public/presets/extensions`: every
// shipped preset must pass its fixtures (this is what would have caught the
// header-case bug F4 fixed).
func TestBundledPresetFixtures(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "public", "presets", "extensions")
	r, err := RunFixtures(dir, FixtureOptions{})
	require.NoError(t, err)
	for _, c := range r.Cases {
		switch c.Status {
		case StatusFail:
			t.Errorf("%s/%s failed: %s", c.Extension, c.Case, strings.Join(c.Failures, "; "))
		case StatusSkip:
			if c.SkipReason != hookSkipReason {
				t.Errorf("%s has no fixtures: ship %s", c.Extension, extensionStem(c.Extension)+fixturesSuffix)
			}
		}
	}
	assert.Greater(t, r.Passed, 10)
}

func TestParseHTTPFixture(t *testing.T) {
	fx, err := parseHTTPFixture([]byte("# handler: scanPerRequest\n// url: https://x.example.com\n" +
		"POST /login HTTP/1.1\nHost: x.example.com\nContent-Length: 99\n\nuser=a&pass=b\n\n" +
		"HTTP/1.1 302 Found\nLocation: /home\nContent-Length: 0\n\n"))
	require.NoError(t, err)
	assert.Equal(t, "scanPerRequest", fx.Directives["handler"])
	assert.Equal(t, "POST /login HTTP/1.1\r\nHost: x.example.com\r\nContent-Length: 13\r\n\r\nuser=a&pass=b", string(fx.Request))
	assert.Equal(t, "HTTP/1.1 302 Found\r\nLocation: /home\r\nContent-Length: 0\r\n\r\n", string(fx.Response))

	rr, err := fx.requestResponse("")
	require.NoError(t, err)
	assert.Equal(t, "https://x.example.com/login", rr.Target())
}

func TestLoadAndRun_HandlerSelection(t *testing.T) {
	ext, err := Load(filepath.Join("testdata", "fixtures", "title_check.js"), Options{})
	require.NoError(t, err)
	assert.Equal(t, "passive", ext.Kind())
	assert.Equal(t, []string{HandlerPerRequest}, ext.DeclaredHandlers())

	fx, err := parseHTTPFixture([]byte("GET /?id=1 HTTP/1.1\nHost: a.example.com\n"))
	require.NoError(t, err)
	rr, err := fx.requestResponse("")
	require.NoError(t, err)

	_, err = ext.Run(rr, RunOptions{Handler: "scanPerInsertionPoint"})
	var ue *UsageError
	require.ErrorAs(t, err, &ue)
	assert.Contains(t, err.Error(), "passive")

	_, err = ext.Run(rr, RunOptions{Handler: "scanPerHost"})
	require.ErrorAs(t, err, &ue)
	_, err = ext.Run(rr, RunOptions{Handler: "nope"})
	require.ErrorAs(t, err, &ue)

	out, err := ext.Run(rr, RunOptions{Handler: "per_request"})
	require.NoError(t, err)
	assert.Equal(t, []string{HandlerPerRequest}, out.Handlers)
	assert.Empty(t, out.Results)

	active, err := Load(filepath.Join("testdata", "fixtures", "reflect_probe.js"), Options{})
	require.NoError(t, err)
	_, err = active.Run(rr, RunOptions{Insertion: "URL_PARAM:missing"})
	require.ErrorAs(t, err, &ue)
	assert.Contains(t, err.Error(), "URL_PARAM:id", "lists the available points")
}

func TestLoad_Failures(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.js")
	require.NoError(t, os.WriteFile(bad, []byte("module.exports = {"), 0o644))
	_, err := Load(bad, Options{})
	var le *LoadError
	require.ErrorAs(t, err, &le)
	assert.Equal(t, "extension_load_failed", string(le.Code()))

	_, err = Load(filepath.Join("testdata", "fixtures", "hook.js"), Options{})
	assert.ErrorIs(t, err, ErrHook)
}
