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
	got, assumed := mergePositionalTargets(
		[]string{" example.com ", "example.com:8443"},
		[]string{"http://example.com", "", "https://example.com"},
	)
	require.Equal(t, []string{
		"http://example.com",
		"http://example.com:8443",
		"https://example.com",
	}, got)
	// Only the lines that carried no scheme. The http:// spelling deduped onto
	// the same entry, and an explicit scheme must never be reported as a guess —
	// the probe sweep uses this set to decide which targets it may re-probe over
	// https, and second-guessing an explicit http:// would defeat the operator.
	require.Equal(t, map[string]struct{}{
		"http://example.com":      {},
		"http://example.com:8443": {},
	}, assumed)
}

// A blank line must stay dropped: without the empty guard in EnsureURLScheme it
// would become "http://" and survive the merge's own blank filter.
func TestMergePositionalTargetsDropsBlanks(t *testing.T) {
	got, assumed := mergePositionalTargets([]string{"", "   "}, nil)
	assert.Empty(t, got)
	assert.Empty(t, assumed)
}
