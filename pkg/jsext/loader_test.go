package jsext

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

// observeLogs swaps the global zap logger for an observer for the test's
// duration and returns the captured entries.
func observeLogs(t *testing.T) *observer.ObservedLogs {
	t.Helper()
	core, logs := observer.New(zap.DebugLevel)
	restore := zap.ReplaceGlobals(zap.New(core))
	t.Cleanup(restore)
	return logs
}

const passiveScriptSrc = `module.exports = {
  id: "conf-check",
  type: "passive",
  severity: "low",
  confidence: "certain",
  confirmationCriteria: ["header is present", "value is not empty"],
  scanPerRequest: function(ctx) { return null; }
};`

// TestLoadScripts_ExplicitPathsSkipNonScripts: --ext with a YAML extension or
// a .d.ts must not be fed to the JS VM (it used to log a spurious
// "Failed to load script"); the JS script beside them still loads.
func TestLoadScripts_ExplicitPathsSkipNonScripts(t *testing.T) {
	logs := observeLogs(t)
	dir := t.TempDir()

	yamlPath := writeTestFile(t, dir, "check.vgm.yaml", "id: check\ntype: passive\n")
	ymlPath := writeTestFile(t, dir, "check2.vgm.yml", "id: check2\ntype: passive\n")
	dtsPath := writeTestFile(t, dir, "vigolium.d.ts", TypeDefinitions())
	jsPath := writeTestFile(t, dir, "conf_check.js", passiveScriptSrc)

	scripts, err := LoadScripts(&config.ExtensionsConfig{
		CustomDir: []string{yamlPath, ymlPath, dtsPath, jsPath},
	})
	require.NoError(t, err)
	require.Len(t, scripts, 1)
	assert.Equal(t, jsPath, scripts[0].Path)

	assert.Zero(t, logs.FilterMessage("Failed to load script").Len(),
		"non-script extension files must not produce load failures")
}

func TestLoadScripts_DirSkipsDeclarationAndYAML(t *testing.T) {
	logs := observeLogs(t)
	dir := t.TempDir()
	writeTestFile(t, dir, "check.vgm.yaml", "id: check\ntype: passive\n")
	writeTestFile(t, dir, "check2.vgm.yml", "id: check2\ntype: passive\n")
	writeTestFile(t, dir, "vigolium.d.ts", TypeDefinitions())
	writeTestFile(t, dir, "conf_check.js", passiveScriptSrc)

	scripts, err := LoadScripts(&config.ExtensionsConfig{ExtensionDir: dir})
	require.NoError(t, err)
	require.Len(t, scripts, 1)
	assert.Zero(t, logs.FilterMessage("Failed to load script").Len())
}

func TestExtract_ConfidenceAndConfirmationCriteria(t *testing.T) {
	meta, err := newMetadataExtractor().Extract(passiveScriptSrc, "conf_check.js")
	require.NoError(t, err)
	assert.Equal(t, "certain", meta.Confidence)
	assert.Equal(t, "header is present\nvalue is not empty", meta.ConfirmationCriteria)

	meta, err = newMetadataExtractor().Extract(`module.exports = {type: "passive", confirmationCriteria: "one line"};`, "x.js")
	require.NoError(t, err)
	assert.Equal(t, "one line", meta.ConfirmationCriteria)
}

func newTestPassiveModule(t *testing.T, script string) *JSPassiveModule {
	t.Helper()
	meta, err := newMetadataExtractor().Extract(script, "conf_check.js")
	require.NoError(t, err)
	mod, err := NewJSPassiveModule(&LoadedScript{Path: "conf_check.js", Source: script, Metadata: *meta}, APIOptions{})
	require.NoError(t, err)
	return mod
}

func testRequestResponse(t *testing.T) *httpmsg.HttpRequestResponse {
	t.Helper()
	svc, err := httpmsg.ParseService("http://example.com")
	require.NoError(t, err)
	req := httpmsg.NewHttpRequestWithService(svc, []byte("GET /a?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhello"))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestJSModule_ConfidencePassthrough(t *testing.T) {
	mod := newTestPassiveModule(t, passiveScriptSrc)
	assert.Equal(t, severity.Certain, mod.Confidence())
	assert.Equal(t, "header is present\nvalue is not empty", mod.ConfirmationCriteria())

	// No confidence declared → module default stays firm.
	mod = newTestPassiveModule(t, `module.exports = {type: "passive", scanPerRequest: function(){ return null; }};`)
	assert.Equal(t, severity.Firm, mod.Confidence())
}

func TestJSModule_PerResultOverrides(t *testing.T) {
	script := `module.exports = {
  id: "per-result",
  type: "passive",
  severity: "low",
  confidence: "firm",
  scanPerRequest: function(ctx) {
    return [
      {name: "a", confidence: "tentative", tags: ["XSS", "reflected"], cwe: "CWE-79",
       param: "id", evidence: ["first", {note: "second", request: "GET /"}]},
      {name: "b", fuzzingParameter: "q"}
    ];
  }
};`
	mod := newTestPassiveModule(t, script)
	results, err := mod.ScanPerRequest(testRequestResponse(t), nil)
	require.NoError(t, err)
	require.Len(t, results, 2)

	a := results[0]
	assert.Equal(t, severity.Tentative, a.Info.Confidence)
	assert.Equal(t, []string{"xss", "reflected"}, a.Info.Tags)
	assert.Equal(t, "CWE-79", a.Metadata["cwe"])
	assert.Equal(t, "id", a.FuzzingParameter)
	require.Len(t, a.AdditionalEvidence, 2)
	assert.Equal(t, "first", a.AdditionalEvidence[0])
	assert.JSONEq(t, `{"note":"second","request":"GET /"}`, a.AdditionalEvidence[1])

	b := results[1]
	// Unset per-result confidence stays undefined so the executor fills in the
	// module default (executor_results.go).
	assert.Equal(t, severity.ConfidenceUndefined, b.Info.Confidence)
	assert.Equal(t, "q", b.FuzzingParameter)
}

func TestLint_InvalidConfidenceIsError(t *testing.T) {
	src := `module.exports = {
  id: "bad-conf",
  type: "passive",
  severity: "low",
  confidence: "sure",
  scanPerRequest: function(ctx) { return null; }
};`
	res := LintSource(src, "bad.js")
	require.True(t, res.HasErrors(), "issues: %+v", res.Issues)
	found := false
	for _, is := range res.Issues {
		if is.Severity == LintError && is.Message == fmt.Sprintf("unknown confidence %q; expected one of: tentative, firm, certain", "sure") {
			found = true
		}
	}
	assert.True(t, found, "issues: %+v", res.Issues)
}
