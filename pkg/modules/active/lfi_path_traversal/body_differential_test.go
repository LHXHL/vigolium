package lfi_path_traversal

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/utils"
)

// TestBodyDifferential_OptIn checks the executor's safety net against this
// module's findings: a finding whose replay still returns the file is kept,
// and the same finding is dropped once the payload response is only
// per-request noise.
func TestBodyDifferential_OptIn(t *testing.T) {
	t.Parallel()
	var _ interface{ ConfirmsByBodyDifferential() bool } = (*Module)(nil)
	require.True(t, New().ConfirmsByBodyDifferential())

	var noisy atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("file")
		switch {
		case noisy.Load():
			_, _ = io.WriteString(w, cleanBaseline+" "+utils.RandomString(12))
		case strings.Contains(v, "..") || strings.Contains(v, "etc/passwd"):
			_, _ = io.WriteString(w, passwdBody)
		default:
			_, _ = io.WriteString(w, cleanBaseline)
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/?file=welcome"), "text/html", cleanBaseline)
	res, err := New().ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "file"), client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res)

	keep := modkit.ReconfirmFinding(client, rr, res[0].Request)
	assert.True(t, keep.Ran && keep.Confirmed, "a reproducible file include must keep the finding: %s", keep.Reason)

	noisy.Store(true)
	drop := modkit.ReconfirmFinding(client, rr, res[0].Request)
	assert.True(t, drop.Ran, drop.Reason)
	assert.False(t, drop.Confirmed, "nondeterministic noise must drop the finding")
}
