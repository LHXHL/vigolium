package secret_detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// TestModule_SupplementalGenericCredential proves the js-miner-derived
// "Generic Credential Assignment" rule surfaces a broad-keyword quoted assignment
// (a `bearer`/`token`/`client_id` value the kingfisher generics don't cover)
// end-to-end — at the low-signal Suspect tier, carrying the suspect-bundle tag so it
// folds into the per-host "Low-confidence secret-shaped matches" bundle rather than a
// standalone High finding. A code-identifier value from the same rule is dropped by
// the shared value-shape guard.
func TestModule_SupplementalGenericCredential(t *testing.T) {
	m := New()

	// A broad-keyword credential assignment with a high-entropy value.
	bundle := `var cfg={bearerToken:"eyQ7wR2nZ9xL4vB8kM3p"};`
	ctx := modtest.HTTPCtx("/test", "application/javascript", bundle)
	findings, err := m.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "broad-keyword credential assignment should surface")

	var got *output.ResultEvent
	for _, f := range findings {
		for _, v := range f.ExtractedResults {
			if v == "eyQ7wR2nZ9xL4vB8kM3p" {
				got = f
			}
		}
	}
	require.NotNil(t, got, "expected the bearerToken value to be reported, got %v", findingValues(findings))
	assert.Equal(t, severity.Suspect, got.Info.Severity, "supplemental generic credential is Suspect, not High")
	assert.Contains(t, got.Info.Tags, output.SuspectBundleTag, "must be tagged for the per-host suspect bundle")

	// A code-identifier value from the same rule family is still dropped by the
	// value-shape guard (kebab slug near a credential keyword).
	slug := `qs("login",{labelPassword:[1,"reset-password-field"]});`
	ctx = modtest.HTTPCtx("/test", "application/javascript", slug)
	findings, err = m.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, findings, "identifier-slug value must be dropped, got %v", findingValues(findings))
}
