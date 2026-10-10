package jsext

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/grafana/sobek"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
)

// TestFuncDefsDeclareEffect: every API def names its effect, so a new API
// cannot default to "pure" (and run for real at load time) by omission.
func TestFuncDefsDeclareEffect(t *testing.T) {
	for _, d := range allFuncDefs() {
		assert.NotEqual(t, EffectUnset, d.Effect, "%s has no Effect", d.FullName())
		assert.NotEqual(t, "unknown", d.Effect.String(), "%s", d.FullName())
	}
}

// TestModeLoad_RegistersEveryNamespace: a load VM sees the runtime's full API
// shape even with no HTTP client, repository, LLM or OAST service.
func TestModeLoad_RegistersEveryNamespace(t *testing.T) {
	vm := sobek.New()
	SetupAPI(vm, APIOptions{Mode: ModeLoad})
	for _, d := range allFuncDefs() {
		if d.MakeHandler == nil {
			continue
		}
		v, err := vm.RunString(d.FullName())
		require.NoError(t, err, d.FullName())
		_, ok := sobek.AssertFunction(v)
		assert.True(t, ok, "%s is not a function in a load VM", d.FullName())
	}
}

func TestStubReturnValue(t *testing.T) {
	vm := sobek.New()
	cases := map[string]string{
		"void":                       "undefined",
		"":                           "undefined",
		"string|null":                "null",
		"OASTPayload | null":         "null",
		"string[]":                   "array",
		"[{id, name}]":               "array",
		"bool":                       "false",
		"boolean":                    "false",
		"string":                     "",
		"number":                     "0",
		"HttpResponse":               "object",
		"{stdout, stderr, exitCode}": "object",
	}
	for returns, want := range cases {
		v := stubReturnValue(vm, returns)
		var got string
		switch {
		case sobek.IsUndefined(v):
			got = "undefined"
		case sobek.IsNull(v):
			got = "null"
		default:
			if _, isArr := v.Export().([]any); isArr {
				got = "array"
			} else if _, isMap := v.Export().(map[string]any); isMap {
				got = "object"
			} else {
				got = v.String()
			}
		}
		assert.Equal(t, want, got, "Returns %q", returns)
	}
}

func lintExt(src string) *LintResult {
	return LintSourceWithOptions(src, "ext.js", LintOptions{Extension: true})
}

func issuesWithRule(r *LintResult, rule string) []LintIssue {
	var out []LintIssue
	for _, is := range r.Issues {
		if is.Rule == rule {
			out = append(out, is)
		}
	}
	return out
}

// TestLint_TopLevelPureAPIIsClean: a pure call at top level runs for real (its
// result feeds the metadata) and is not reported.
func TestLint_TopLevelPureAPIIsClean(t *testing.T) {
	src := `var u = vigolium.parse.url("https://example.com/admin?x=1");
module.exports = {
  id: "pure-top",
  type: "passive",
  severity: "info",
  description: "host " + u.host,
  scanPerRequest: function(ctx) { return null; }
};`
	res := lintExt(src)
	assert.Empty(t, res.Issues)

	meta, err := newMetadataExtractor().Extract(src, "pure-top.js")
	require.NoError(t, err)
	assert.Equal(t, "host example.com", meta.Description)
}

// TestLint_TopLevelHTTPIsStubbedWarning: a top-level vigolium.http.get loads
// (stubbed, nothing sent, no nil HTTP client dereferenced) and lint names it
// with its line.
func TestLint_TopLevelHTTPIsStubbedWarning(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()

	src := `var warm = vigolium.http.get("` + srv.URL + `/warm");
module.exports = {
  id: "http-top",
  type: "passive",
  severity: "info",
  scanPerRequest: function(ctx) { return null; }
};`
	res := lintExt(src)
	assert.False(t, res.HasErrors(), "%+v", res.Issues)
	effects := issuesWithRule(res, RuleTopLevelEffect)
	require.Len(t, effects, 1, "%+v", res.Issues)
	assert.Equal(t, LintWarning, effects[0].Severity)
	assert.Equal(t, 1, effects[0].Line)
	assert.Contains(t, effects[0].Message, "vigolium.http.get")

	dir := t.TempDir()
	path := writeTestFile(t, dir, "http_top.js", src)
	scripts, failures := LoadScriptsReport(&config.ExtensionsConfig{CustomDir: []string{path}})
	assert.Empty(t, failures)
	require.Len(t, scripts, 1)
	assert.Equal(t, "http-top", scripts[0].Metadata.ID)
	assert.Zero(t, hits.Load(), "loading or linting must not send traffic")
}

// TestLoad_TopLevelExecAndWriteAreStubbed: exec and writeFile at top level never
// run during load, even with exec allowed.
func TestLoad_TopLevelExecAndWriteAreStubbed(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "exec-ran")
	written := filepath.Join(dir, "written")
	src := `vigolium.utils.exec("touch ` + marker + `");
vigolium.utils.writeFile("` + written + `", "x");
module.exports = {
  id: "exec-top",
  type: "post_hook",
  execute: function(result) { return result; }
};`
	path := writeTestFile(t, dir, "exec_top.js", src)
	scripts, failures := LoadScriptsReport(&config.ExtensionsConfig{CustomDir: []string{path}, AllowExec: true, SandboxDir: dir})
	assert.Empty(t, failures)
	require.Len(t, scripts, 1)

	res := lintExt(src)
	assert.Len(t, issuesWithRule(res, RuleTopLevelEffect), 2, "%+v", res.Issues)

	for _, p := range []string{marker, written} {
		_, err := os.Stat(p)
		assert.True(t, os.IsNotExist(err), "%s was created at load time", p)
	}
}

// TestLint_MissingHandlerIsError: a declared scan type whose handler is absent
// (or not a function) is an error — the runtime would skip it silently.
func TestLint_MissingHandlerIsError(t *testing.T) {
	src := `module.exports = {
  id: "no-handler",
  type: "active",
  severity: "high",
  scanTypes: ["per_insertion_point", "per_request"],
  scanPerRequest: "not a function",
  // a comment mentioning scanPerInsertionPoint: must not satisfy the check
};`
	res := lintExt(src)
	require.True(t, res.HasErrors())
	missing := issuesWithRule(res, RuleMissingHandler)
	require.Len(t, missing, 2, "%+v", res.Issues)
	assert.Contains(t, missing[0].Message+missing[1].Message, "scanPerInsertionPoint")
	assert.Contains(t, missing[0].Message+missing[1].Message, "scanPerRequest")
}

// TestLint_NoExports: an extension that exports nothing is an error when it was
// named as an extension, unless it carries the plain-script pragma.
func TestLint_NoExports(t *testing.T) {
	src := "var x = vigolium.utils.md5('a');\n"
	res := lintExt(src)
	require.Len(t, issuesWithRule(res, RuleNoExports), 1, "%+v", res.Issues)
	assert.True(t, res.HasErrors())

	assert.Empty(t, lintExt(ScriptPragma+"\n"+src).Issues)
	assert.Empty(t, LintSource(src, "snippet.js").Issues, "a snippet not named as an extension is not held to it")
}

// TestLint_MetadataFailureIsErrorWithLine: top-level code that throws fails
// the load; lint reports it as an error at the throwing line.
func TestLint_MetadataFailureIsErrorWithLine(t *testing.T) {
	src := `var a = 1;
var cfg = undefinedThing.value;
module.exports = { id: "boom", type: "passive", scanPerRequest: function(){ return null; } };`
	res := lintExt(src)
	meta := issuesWithRule(res, RuleMetadata)
	require.Len(t, meta, 1, "%+v", res.Issues)
	assert.Equal(t, LintError, meta[0].Severity)
	assert.Equal(t, 2, meta[0].Line)
}

func TestLoad_TopLevelInfiniteLoopTimesOut(t *testing.T) {
	prev := loadTimeout
	loadTimeout = 200 * time.Millisecond
	t.Cleanup(func() { loadTimeout = prev })

	start := time.Now()
	_, err := newMetadataExtractor().Extract(`while (true) {}`, "loop.js")
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
}

// TestLoadScriptsReport_Failures: every failure carries its stage, and Explicit
// is true only for files named in custom_dir.
func TestLoadScriptsReport_Failures(t *testing.T) {
	extDir := t.TempDir()
	writeTestFile(t, extDir, "dir_bad.js", `throw new Error("dir");`)
	writeTestFile(t, extDir, "dir_ok.js", passiveScriptSrc)

	other := t.TempDir()
	syntax := writeTestFile(t, other, "syntax.js", `module.exports = {`)
	noType := writeTestFile(t, other, "notype.js", `module.exports = {id: "x"};`)
	badTS := writeTestFile(t, other, "bad.ts", `const x: = ;`)
	missing := filepath.Join(other, "missing.js")

	scripts, failures := LoadScriptsReport(&config.ExtensionsConfig{
		ExtensionDir: extDir,
		CustomDir:    []string{syntax, noType, badTS, missing},
	})
	require.Len(t, scripts, 1)
	assert.False(t, scripts[0].Explicit)

	byPath := map[string]LoadFailure{}
	for _, f := range failures {
		byPath[filepath.Base(f.Path)] = f
	}
	require.Len(t, byPath, 5, "%+v", failures)
	assert.False(t, byPath["dir_bad.js"].Explicit)
	assert.Equal(t, LoadStageMetadata, byPath["dir_bad.js"].Stage)
	assert.Equal(t, LoadStageCompile, byPath["syntax.js"].Stage)
	assert.Equal(t, LoadStageMetadata, byPath["notype.js"].Stage)
	assert.Equal(t, LoadStageTranspile, byPath["bad.ts"].Stage)
	assert.Equal(t, LoadStageRead, byPath["missing.js"].Stage)
	for _, name := range []string{"syntax.js", "notype.js", "bad.ts", "missing.js"} {
		assert.True(t, byPath[name].Explicit, name)
	}
}

// TestNewEngine_Failures: engine-level failures (unknown type, YAML schema in
// strict mode) join the loader's, and ExplicitFailures filters to --ext ones.
func TestNewEngine_Failures(t *testing.T) {
	dir := t.TempDir()
	unknownType := writeTestFile(t, dir, "weird.js", `module.exports = {id: "weird", type: "activ"};`)
	typo := writeTestFile(t, dir, "typo.vgm.yaml", "id: typo\ntype: passive\nmatchers_condtion: and\nmatchers:\n  - contains: x\n")
	good := writeTestFile(t, dir, "good.vgm.yaml", "id: good\ntype: passive\nmatchers:\n  - contains: x\n")

	cfg := &config.ExtensionsConfig{Enabled: true, CustomDir: []string{unknownType, typo, good}}
	e, err := NewEngine(cfg, nil, nil)
	require.NoError(t, err)
	require.Len(t, e.Failures(), 1, "lenient YAML: the typo only warns; %+v", e.Failures())
	assert.Equal(t, LoadStageUnknownType, e.Failures()[0].Stage)
	assert.Len(t, e.PassiveModules(), 2)

	cfg.YAMLStrict = true
	e, err = NewEngine(cfg, nil, nil)
	require.NoError(t, err)
	require.Len(t, e.ExplicitFailures(), 2, "%+v", e.Failures())
	var schema LoadFailure
	for _, f := range e.Failures() {
		if f.Stage == LoadStageSchema {
			schema = f
		}
	}
	require.NotNil(t, schema.Err)
	assert.Contains(t, schema.Err.Error(), `did you mean "matchers_condition"`)
	assert.Contains(t, schema.Err.Error(), ":3:")
	assert.True(t, strings.HasSuffix(schema.Path, "typo.vgm.yaml"))
}

// TestLint_ConfigKeysAreNotUnknownAPIs: vigolium.config.<key> names a user
// variable, not an API function.
func TestLint_ConfigKeysAreNotUnknownAPIs(t *testing.T) {
	res := LintSource(`var t = vigolium.config.auth_token || "";`, "cfg.js")
	assert.Empty(t, issuesWithRule(res, RuleUnknownAPI))
}
