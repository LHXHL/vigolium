package ssi_injection

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// TestBodyDifferential_PerResult checks the per-result opt-in: the in-band echo
// result is re-confirmed (kept while the server keeps evaluating, dropped once
// the payload response is only noise) and an OAST-signal result never is.
func TestBodyDifferential_PerResult(t *testing.T) {
	t.Parallel()
	var _ interface {
		ConfirmsResultByBodyDifferential(*output.ResultEvent) bool
	} = (*Module)(nil)

	var noisy atomic.Bool
	page := ssiPage()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if noisy.Load() {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(htmlPage(utils.RandomString(12))))
			return
		}
		page(w, r)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/page.shtml?q=hello")
	res, err := New().ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "q"), client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res)
	assert.Equal(t, output.SignalInband, res[0].Signal())
	require.True(t, New().ConfirmsResultByBodyDifferential(res[0]))

	keep := modkit.ReconfirmFinding(client, rr, res[0].Request)
	assert.True(t, keep.Ran && keep.Confirmed, "a reproducible evaluation must keep the finding: %s", keep.Reason)

	noisy.Store(true)
	drop := modkit.ReconfirmFinding(client, rr, res[0].Request)
	assert.True(t, drop.Ran, drop.Reason)
	assert.False(t, drop.Confirmed, "nondeterministic noise must drop the finding")

	oast := &output.ResultEvent{}
	oast.SetSignal(output.SignalOAST)
	assert.False(t, New().ConfirmsResultByBodyDifferential(oast), "an OAST result is never body-diff re-confirmed")
}
