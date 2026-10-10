package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/jsext"
)

func TestExtensionsTypes_StdoutAndOutputPaths(t *testing.T) {
	out := captureStdout(t, func() {
		require.NoError(t, runExtensionsTypes(extensionsTypesCmd, ""))
	})
	assert.Equal(t, jsext.TypeDefinitions(), out)

	// -o <dir> writes <dir>/vigolium.d.ts.
	dir := t.TempDir()
	require.NoError(t, runExtensionsTypes(extensionsTypesCmd, dir))
	data, err := os.ReadFile(filepath.Join(dir, jsext.TypeDefinitionsFileName))
	require.NoError(t, err)
	assert.Equal(t, jsext.TypeDefinitions(), string(data))

	// -o <file> writes exactly that file.
	file := filepath.Join(t.TempDir(), "api.d.ts")
	require.NoError(t, runExtensionsTypes(extensionsTypesCmd, file))
	data, err = os.ReadFile(file)
	require.NoError(t, err)
	assert.Equal(t, jsext.TypeDefinitions(), string(data))
}

func TestExtensionsPreset_WritesTypeDefinitions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	prevConfig := globalConfig
	globalConfig = ""
	t.Cleanup(func() { globalConfig = prevConfig })

	captureStdout(t, func() {
		require.NoError(t, installPresets(extensionsPresetCmd, ""))
	})

	extDir := filepath.Join(home, ".vigolium", "extensions")
	data, err := os.ReadFile(filepath.Join(extDir, jsext.TypeDefinitionsFileName))
	require.NoError(t, err, "ext preset must write vigolium.d.ts beside the presets")
	assert.Equal(t, jsext.TypeDefinitions(), string(data))

	// A filter matching no preset is an error, not a silent exit 0.
	captureStdout(t, func() {
		assert.Error(t, installPresets(extensionsPresetCmd, "no-such-preset-xyz"))
	})
}

func TestExtensionsDocsJSON(t *testing.T) {
	prev := globalJSON
	globalJSON = true
	t.Cleanup(func() { globalJSON = prev })

	out := captureStdout(t, func() {
		require.NoError(t, emitExtensionDocsJSON("sha256"))
	})
	var doc struct {
		Items []apiFunctionView `json:"items"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), "ext docs -j must print JSON, got:\n%s", out)
	require.NotEmpty(t, doc.Items)
	found := false
	for _, it := range doc.Items {
		if it.FullName == "vigolium.utils.sha256" {
			found = true
		}
	}
	assert.True(t, found, "items: %+v", doc.Items)

	// No match is an empty list, still valid JSON.
	out = captureStdout(t, func() {
		require.NoError(t, emitExtensionDocsJSON("zzz-no-such-function"))
	})
	doc.Items = nil
	require.NoError(t, json.Unmarshal([]byte(out), &doc))
	assert.Empty(t, doc.Items)
}

func TestExtensionsDocsAndExampleReturnErrors(t *testing.T) {
	captureStdout(t, func() {
		assert.Error(t, printExtensionDocs("zzz-no-such-function"))
		assert.Error(t, printExtensionExamples(extensionsExampleCmd, "zzz-no-such-example"))
	})

	prev := exampleLang
	exampleLang = "ruby"
	t.Cleanup(func() { exampleLang = prev })
	captureStdout(t, func() {
		assert.Error(t, printExtensionExamples(extensionsExampleCmd, ""))
	})
}
