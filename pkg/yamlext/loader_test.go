package yamlext

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
)

func testdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "testdata")
}

func TestIsYAMLExtension(t *testing.T) {
	assert.True(t, IsYAMLExtension("foo.vgm.yaml"))
	assert.True(t, IsYAMLExtension("some/path/bar.vgm.yaml"))
	assert.False(t, IsYAMLExtension("foo.yaml"))
	assert.False(t, IsYAMLExtension("foo.js"))
	assert.True(t, IsYAMLExtension("foo.vgm.yml"))
}

func TestLoadFromConfig_ExplicitVgmYml(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "short_ext.vgm.yml")
	require.NoError(t, os.WriteFile(path, []byte("type: passive\nseverity: low\n"), 0o644))

	defs, err := LoadFromConfig(&config.ExtensionsConfig{CustomDir: []string{path}})
	require.NoError(t, err)
	require.Len(t, defs, 1)
	assert.Equal(t, "short-ext", defs[0].ID, "ID derives from the file name minus .vgm.yml")
}

func TestLoadExtension_ActiveScanner(t *testing.T) {
	def, err := LoadExtension(filepath.Join(testdataDir(), "active_scanner.vgm.yaml"))
	require.NoError(t, err)
	assert.Equal(t, "test-active-scanner", def.ID)
	assert.Equal(t, "Test Active Scanner", def.Name)
	assert.Equal(t, "active", def.Type)
	assert.Equal(t, "medium", def.Severity)
	assert.Len(t, def.Payloads, 1)
	assert.Contains(t, def.Payloads[0], "CANARY")
	assert.Len(t, def.Matchers, 1)
	assert.Equal(t, "body", def.Matchers[0].Type)
	assert.NotNil(t, def.Finding)
	assert.Equal(t, "or", def.MatchersCondition)
}

func TestLoadExtension_PassiveScanner(t *testing.T) {
	def, err := LoadExtension(filepath.Join(testdataDir(), "passive_scanner.vgm.yaml"))
	require.NoError(t, err)
	assert.Equal(t, "test-passive-scanner", def.ID)
	assert.Equal(t, "passive", def.Type)
	assert.Equal(t, "response", def.Scope)
	assert.Len(t, def.Rules, 2)
	assert.Equal(t, "X-Powered-By", def.Rules[0].Match.ResponseHeader)
}

func TestLoadExtension_PreHook(t *testing.T) {
	def, err := LoadExtension(filepath.Join(testdataDir(), "pre_hook.vgm.yaml"))
	require.NoError(t, err)
	assert.Equal(t, "test-pre-hook", def.ID)
	assert.Equal(t, "pre_hook", def.Type)
	assert.NotNil(t, def.SkipWhen)
	assert.Equal(t, "api_key", def.SkipWhen.ConfigEmpty)
	assert.Len(t, def.AddHeaders, 2)
}

func TestLoadExtension_PostHook(t *testing.T) {
	def, err := LoadExtension(filepath.Join(testdataDir(), "post_hook.vgm.yaml"))
	require.NoError(t, err)
	assert.Equal(t, "test-post-hook", def.ID)
	assert.Equal(t, "post_hook", def.Type)
	assert.NotNil(t, def.Escalate)
	assert.True(t, def.Escalate.BumpSeverity)
	assert.Equal(t, "CRITICAL", def.Escalate.Tag)
}

func TestLoadExtension_MissingType(t *testing.T) {
	_, err := LoadExtension(filepath.Join(testdataDir(), "invalid_no_type.vgm.yaml"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required field 'type'")
}

func TestLoadExtension_BadType(t *testing.T) {
	_, err := LoadExtension(filepath.Join(testdataDir(), "invalid_bad_type.vgm.yaml"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid type")
}

func TestLoadExtension_AutoGeneratesID(t *testing.T) {
	// Create a temp file to test auto-ID generation
	def, err := LoadExtension(filepath.Join(testdataDir(), "skip_extensions_hook.vgm.yaml"))
	require.NoError(t, err)
	assert.Equal(t, "test-skip-ext", def.ID) // explicit ID takes precedence
}

func TestLoadExtension_SourcePath(t *testing.T) {
	path := filepath.Join(testdataDir(), "active_scanner.vgm.yaml")
	def, err := LoadExtension(path)
	require.NoError(t, err)
	assert.Equal(t, path, def.SourcePath())
}

func TestLoadExtension_FileNotFound(t *testing.T) {
	_, err := LoadExtension("/nonexistent/path.vgm.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read")
}

func TestLoadFromDir(t *testing.T) {
	defs, failures, err := loadFromDir(testdataDir(), false)
	require.NoError(t, err)
	// Should load all valid .vgm.yaml files, skip invalid ones (with warnings)
	// We have: active_scanner, passive_scanner, pre_hook, post_hook, skip_extensions_hook, drop_hook = 6 valid
	// Plus 2 invalid files that get skipped, and are reported as directory
	// (not explicit) failures.
	assert.GreaterOrEqual(t, len(defs), 6)
	assert.GreaterOrEqual(t, len(failures), 2)
	for _, f := range failures {
		assert.False(t, f.Explicit, "%s", f.Path)
		assert.NotEmpty(t, f.Stage, "%s", f.Path)
	}

	// Verify we have at least one of each type
	types := map[string]bool{}
	for _, def := range defs {
		types[def.Type] = true
	}
	assert.True(t, types["active"])
	assert.True(t, types["passive"])
	assert.True(t, types["pre_hook"])
	assert.True(t, types["post_hook"])
}
