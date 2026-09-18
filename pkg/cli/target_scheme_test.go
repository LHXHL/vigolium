package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The merge is where normalization has to happen for the CLI specifically: it is
// what makes a schemeless target and its http:// spelling one entry rather than
// two, and the normalized form is what the banner prints.
func TestMergePositionalTargetsNormalizesAndDedupes(t *testing.T) {
	got := mergePositionalTargets(
		[]string{" example.com ", "example.com:8443"},
		[]string{"http://example.com", "", "https://example.com"},
	)
	require.Equal(t, []string{
		"http://example.com",
		"http://example.com:8443",
		"https://example.com",
	}, got)
}

// A blank line must stay dropped: without the empty guard in EnsureURLScheme it
// would become "http://" and survive the merge's own blank filter.
func TestMergePositionalTargetsDropsBlanks(t *testing.T) {
	assert.Empty(t, mergePositionalTargets([]string{"", "   "}, nil))
}
