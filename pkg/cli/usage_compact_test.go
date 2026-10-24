package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --usage prints one line per flag, small enough to read whole, and answers
// before cobra validates the command line.
func TestUsageFlagPrintsOneLinePerFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	e := newB5Env(t)
	code, stdout, stderr := e.run(t, nil, "fuzz", "--usage")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Less(t, len(stdout), 12*1024, "the usage view is a fraction of --help")
	assert.Contains(t, stdout, "-w, --wordlist stringArray")
	assert.Contains(t, stdout, "global flags:")
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		assert.NotContains(t, line, "Examples", "no examples in the usage view")
	}

	// A required argument does not stand in the way: `schema command` needs one.
	code, stdout, stderr = e.run(t, nil, "schema", "command", "--usage")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Contains(t, stdout, "schema command")

	code, stdout, stderr = e.run(t, nil, "traffic", "body", "--usage", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	doc := oneDoc(t, stdout, stderr)
	validateRegisteredMap(t, doc)
	assert.Equal(t, "schema flags", doc["command"])
	assert.Equal(t, "traffic body", doc["for_command"])
	names := []string{}
	for _, it := range doc["items"].([]any) {
		names = append(names, it.(map[string]any)["name"].(string))
	}
	assert.Contains(t, names, "uuid")
	assert.Contains(t, names, "representation")

	code, stdout, stderr = e.run(t, nil, "schema", "flags", "replay", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Equal(t, "replay", oneDoc(t, stdout, stderr)["for_command"])
}
