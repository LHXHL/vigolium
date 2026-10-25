package cli

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/agent/recon"
)

// `run probe --favicon` fetches the icon the page links, once, and stores its
// hash as a host fact: `hosts` shows favicon_mmh3, and every http_record line
// of the jsonl export carries the favicon object. Without the flag the sweep
// asks for no icon.
func TestProbeFaviconStoresIconHash(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	f := newFingerprintFixture(t)
	home := a3Home(t, "*")
	want := recon.ShodanFaviconHash(fixtureIcon)

	out := filepath.Join(t.TempDir(), "probe.jsonl")
	code, stdout, stderr := runA3(t, home, "run", "probe", "-t", f.srv.URL, "--favicon",
		"--format", "jsonl", "--export-only", "http", "-o", out)
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	f.mu.Lock()
	iconReads := len(f.hitsAt["/static/icon.png"])
	f.mu.Unlock()
	assert.Equal(t, 1, iconReads, "one icon read per origin")

	code, stdout, stderr = runA3(t, home, "hosts", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	doc := oneDoc(t, stdout, stderr)
	validateRegisteredMap(t, doc)
	host := doc["items"].([]any)[0].(map[string]any)
	assert.EqualValues(t, want, host["favicon_mmh3"])
	assert.Equal(t, f.srv.URL+"/static/icon.png", host["favicon"].(map[string]any)["url"])
	assert.NotContains(t, host, "fingerprint", "the probe stores the icon, not a fingerprint report")

	file, err := os.Open(out)
	require.NoError(t, err)
	defer func() { _ = file.Close() }()
	records := 0
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var line struct {
			Type string         `json:"type"`
			Data map[string]any `json:"data"`
		}
		require.NoError(t, json.Unmarshal(sc.Bytes(), &line))
		if line.Type != "http_record" {
			continue
		}
		records++
		icon, ok := line.Data["favicon"].(map[string]any)
		require.True(t, ok, "http_record line without favicon: %v", line.Data["url"])
		assert.EqualValues(t, want, icon["mmh3"])
		assert.NotEmpty(t, icon["md5"])
		assert.Equal(t, f.srv.URL+"/static/icon.png", icon["url"])
	}
	require.NoError(t, sc.Err())
	assert.Positive(t, records)

	// Without --favicon the sweep sends no icon read.
	home2 := a3Home(t, "*")
	code, stdout, stderr = runA3(t, home2, "run", "probe", "-t", f.srv.URL, "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	f.mu.Lock()
	assert.Equal(t, 1, len(f.hitsAt["/static/icon.png"]), "no icon read without --favicon")
	f.mu.Unlock()
}
