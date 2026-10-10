package yamlext

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
)

const typoYAML = `id: typo
type: active
severity: high
scan_types: [per_insertion_point]
payloads:
  - "x"
matchers_condtion: and
matchers:
  - type: body
    contians: "49"
`

// TestLintYAML_UnknownKeyWithSuggestionAndLine: every unknown key is an error
// at its own line, with the closest real key suggested.
func TestLintYAML_UnknownKeyWithSuggestionAndLine(t *testing.T) {
	res := LintYAML(typoYAML, "typo.vgm.yaml")
	require.True(t, res.HasErrors())
	var unknown []YAMLLintIssue
	for _, is := range res.Issues {
		if is.Rule == "yaml-unknown-key" {
			unknown = append(unknown, is)
		}
	}
	require.Len(t, unknown, 2, "%+v", res.Issues)
	assert.Equal(t, 7, unknown[0].Line)
	assert.Equal(t, 1, unknown[0].Col)
	assert.Equal(t, `unknown key "matchers_condtion" (did you mean "matchers_condition"?)`, unknown[0].Message)
	assert.Equal(t, 10, unknown[1].Line)
	assert.Contains(t, unknown[1].Message, `matchers[0].contians`)
	assert.Contains(t, unknown[1].Message, `did you mean "contains"?`)
}

// TestLintYAML_PositionsOnSemanticIssues: semantic issues point at their key.
func TestLintYAML_PositionsOnSemanticIssues(t *testing.T) {
	src := "id: x\ntype: passive\nseverity: huge\nmatchers:\n  - type: body\n    regex: \"([\"\n"
	res := LintYAML(src, "x.vgm.yaml")
	lines := map[string]int{}
	for _, is := range res.Issues {
		lines[is.Rule] = is.Line
	}
	assert.Equal(t, 3, lines["bad-severity"], "%+v", res.Issues)
	assert.Equal(t, 6, lines["bad-regex"], "%+v", res.Issues)
}

// TestLintYAML_PayloadsNeedPerInsertionPoint: payloads only run under
// per_insertion_point; without it (the default is per_request) they are dead.
func TestLintYAML_PayloadsNeedPerInsertionPoint(t *testing.T) {
	src := "id: p\ntype: active\nseverity: high\npayloads:\n  - x\nmatchers:\n  - contains: x\n"
	res := LintYAML(src, "p.vgm.yaml")
	var hit *YAMLLintIssue
	for i := range res.Issues {
		if res.Issues[i].Rule == "payloads-unused" {
			hit = &res.Issues[i]
		}
	}
	require.NotNil(t, hit, "%+v", res.Issues)
	assert.Equal(t, "warning", hit.Severity)
	assert.Equal(t, 4, hit.Line)

	ok := LintYAML("id: p\ntype: active\nseverity: high\nscan_types: [per_insertion_point]\npayloads:\n  - x\nmatchers:\n  - contains: x\n", "p.vgm.yaml")
	for _, is := range ok.Issues {
		assert.NotEqual(t, "payloads-unused", is.Rule)
	}
}

// TestLoadFromConfigReport_Strict: with yaml_strict an unknown key fails the
// load (explicit for custom_dir); without it the file loads.
func TestLoadFromConfigReport_Strict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "typo.vgm.yaml")
	require.NoError(t, os.WriteFile(path, []byte(typoYAML), 0o644))

	defs, failures := LoadFromConfigReport(&config.ExtensionsConfig{CustomDir: []string{path}})
	assert.Empty(t, failures)
	require.Len(t, defs, 1)
	assert.True(t, defs[0].Explicit())

	defs, failures = LoadFromConfigReport(&config.ExtensionsConfig{CustomDir: []string{path}, YAMLStrict: true})
	assert.Empty(t, defs)
	require.Len(t, failures, 1)
	f := failures[0]
	assert.True(t, f.Explicit)
	assert.Equal(t, StageSchema, f.Stage)
	assert.Contains(t, f.Err.Error(), `typo.vgm.yaml:7: unknown key "matchers_condtion" (did you mean "matchers_condition"?) (and 1 more)`)
}
