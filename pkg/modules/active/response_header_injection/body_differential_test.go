package response_header_injection

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

// TestBodyDifferential_PerResult checks the per-result opt-in on a genuine
// header split: kept while the injected header keeps coming back, dropped once
// the server answers with noise only.
func TestBodyDifferential_PerResult(t *testing.T) {
	t.Parallel()
	var _ interface {
		ConfirmsResultByBodyDifferential(*output.ResultEvent) bool
	} = (*Module)(nil)

	var noisy atomic.Bool
	split := headerSplitServer()
	defer split.Close()
	splitHandler := split.Config.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if noisy.Load() {
			_, _ = w.Write([]byte("ok " + utils.RandomString(12)))
			return
		}
		splitHandler.ServeHTTP(w, r)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=test")
	res, err := New().ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "q"), client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res)
	assert.Equal(t, output.SignalInband, res[0].Signal())
	require.True(t, New().ConfirmsResultByBodyDifferential(res[0]), "technique %v", res[0].Metadata[metaTechnique])

	keep := modkit.ReconfirmFinding(client, rr, res[0].Request)
	assert.True(t, keep.Ran && keep.Confirmed, "a reproducible header split must keep the finding: %s", keep.Reason)

	noisy.Store(true)
	drop := modkit.ReconfirmFinding(client, rr, res[0].Request)
	assert.True(t, drop.Ran, drop.Reason)
	assert.False(t, drop.Confirmed, "nondeterministic noise must drop the finding")
}

// TestConfirmsResultByBodyDifferential_SetCookieExcluded: the differential
// strips Set-Cookie lines, so the cookie techniques must not opt in.
func TestConfirmsResultByBodyDifferential_SetCookieExcluded(t *testing.T) {
	t.Parallel()
	m := New()
	for _, p := range m.payloads {
		r := &output.ResultEvent{Metadata: resultMetadata(p.name)}
		want := p.name != "crlf-setcookie" && p.name != "crlf-setcookie-encoded"
		assert.Equal(t, want, m.ConfirmsResultByBodyDifferential(r), p.name)
	}
	assert.False(t, m.ConfirmsResultByBodyDifferential(&output.ResultEvent{}))
}
