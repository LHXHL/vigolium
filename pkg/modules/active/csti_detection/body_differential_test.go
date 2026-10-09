package csti_detection

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/utils"
)

// TestBodyDifferential_OptIn checks the executor's safety net against this
// module's findings: a finding whose replay still reflects the expression is
// kept, and the same finding is dropped once the payload response is only
// per-request noise.
func TestBodyDifferential_OptIn(t *testing.T) {
	t.Parallel()
	var _ interface{ ConfirmsByBodyDifferential() bool } = (*Module)(nil)
	require.True(t, New().ConfirmsByBodyDifferential())

	var noisy atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		q := r.URL.Query().Get("q")
		if noisy.Load() {
			q = utils.RandomString(12)
		}
		_, _ = w.Write([]byte(`<html><body ng-app="myApp"><div id="app">` + q + `</div></body></html>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/page?q=hello"),
		"text/html",
		`<html><body ng-app="myApp"><div id="app">Hello</div></body></html>`,
	)
	res, err := New().ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "q"), client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res)

	keep := modkit.ReconfirmFinding(client, rr, res[0].Request)
	assert.True(t, keep.Ran && keep.Confirmed, "a reproducible reflection must keep the finding: %s", keep.Reason)

	noisy.Store(true)
	drop := modkit.ReconfirmFinding(client, rr, res[0].Request)
	assert.True(t, drop.Ran, drop.Reason)
	assert.False(t, drop.Confirmed, "nondeterministic noise must drop the finding")
}
