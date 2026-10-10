package xxe_generic

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
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// TestBodyDifferential_PerResult checks the per-result opt-in: the in-band
// result is re-confirmed (kept while the file keeps coming back, dropped once
// the payload response is only noise) and an OAST-signal result never is.
func TestBodyDifferential_PerResult(t *testing.T) {
	t.Parallel()
	var _ interface {
		ConfirmsResultByBodyDifferential(*output.ResultEvent) bool
	} = (*Module)(nil)

	var noisy atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/xml")
		if noisy.Load() {
			_, _ = w.Write([]byte("<result>" + utils.RandomString(12) + "</result>"))
			return
		}
		if strings.Contains(string(body), "etc/passwd") {
			_, _ = w.Write([]byte("<result>root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin</result>"))
			return
		}
		_, _ = w.Write([]byte("<result>ok</result>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/api/orders", seedXML)
	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res)
	assert.Equal(t, output.SignalInband, res[0].Signal())
	require.True(t, New().ConfirmsResultByBodyDifferential(res[0]))

	keep := modkit.ReconfirmFinding(client, rr, res[0].Request)
	assert.True(t, keep.Ran && keep.Confirmed, "a reproducible file read must keep the finding: %s", keep.Reason)

	noisy.Store(true)
	drop := modkit.ReconfirmFinding(client, rr, res[0].Request)
	assert.True(t, drop.Ran, drop.Reason)
	assert.False(t, drop.Confirmed, "nondeterministic noise must drop the finding")

	oast := &output.ResultEvent{}
	oast.SetSignal(output.SignalOAST)
	assert.False(t, New().ConfirmsResultByBodyDifferential(oast), "an OAST result is never body-diff re-confirmed")
	assert.False(t, New().ConfirmsResultByBodyDifferential(&output.ResultEvent{}), "an unmarked result is not opted in")
}
