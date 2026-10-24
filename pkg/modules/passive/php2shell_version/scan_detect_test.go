package php2shell_version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestScanPerRequest_UnpatchedPoweredBy(t *testing.T) {
	t.Parallel()
	ctx := modtest.HTTPCtxHeaders("/", "Content-Type: text/html\r\nX-Powered-By: PHP/8.3.12\r\n", `<html></html>`)

	results, err := New().ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, severity.Info, results[0].Info.Severity)
	assert.Equal(t, "8.3.12", results[0].Metadata["version"])
	assert.Equal(t, "8.3.36", results[0].Metadata["fixed_release"])
}

func TestScanPerRequest_UnpatchedServerHeader(t *testing.T) {
	t.Parallel()
	ctx := modtest.HTTPCtxHeaders("/", "Server: Apache/2.4.62 (Debian) PHP/8.2.20\r\n", `ok`)

	results, err := New().ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "8.2.35", results[0].Metadata["fixed_release"])
}

func TestScanPerRequest_NoFinding(t *testing.T) {
	t.Parallel()
	for name, headers := range map[string]string{
		"patched":    "X-Powered-By: PHP/8.4.27\r\n",
		"eol branch": "X-Powered-By: PHP/7.4.33\r\n",
		"no version": "X-Powered-By: PHP\r\n",
		"not php":    "X-Powered-By: Express\r\n",
		"no headers": "Content-Type: text/html\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := modtest.HTTPCtxHeaders("/", headers, `ok`)
			results, err := New().ScanPerRequest(ctx, &modkit.ScanContext{})
			require.NoError(t, err)
			assert.Empty(t, results)
		})
	}
}
