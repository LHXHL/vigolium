package nosqli_operator_injection

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// TestBodyDifferential_PerResult checks the per-result opt-in on a real
// auth-bypass finding: kept while the operator still opens the gate, dropped
// once every response is only noise.
func TestBodyDifferential_PerResult(t *testing.T) {
	t.Parallel()
	var _ interface {
		ConfirmsResultByBodyDifferential(*output.ResultEvent) bool
	} = (*Module)(nil)

	var noisy atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if noisy.Load() {
			_, _ = w.Write([]byte("<html><body>" + utils.RandomString(12) + "</body></html>"))
			return
		}
		if strings.Contains(r.URL.Query().Get("user"), "$ne") || strings.Contains(r.URL.RawQuery, "%24ne") {
			_, _ = w.Write([]byte("<html><body>Welcome back administrator. Account settings and billing records.</body></html>"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html><body>denied</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	bare := modtest.Request(t, srv.URL+"/account?user=alice")
	rr := httpmsg.NewHttpRequestResponse(bare.Request(), httpmsg.NewHttpResponse([]byte(
		"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n<html><body>denied</body></html>")))

	res, err := New().ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "user"), client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "the operator opening a 403 gate must be reported")
	assert.Equal(t, output.SignalInband, res[0].Signal())
	assert.Equal(t, detectionAuthBypass, res[0].Metadata[metaDetection])
	require.True(t, New().ConfirmsResultByBodyDifferential(res[0]))

	keep := modkit.ReconfirmFinding(client, rr, res[0].Request)
	assert.True(t, keep.Ran && keep.Confirmed, "a reproducible bypass must keep the finding: %s", keep.Reason)

	noisy.Store(true)
	drop := modkit.ReconfirmFinding(client, rr, res[0].Request)
	assert.True(t, drop.Ran, drop.Reason)
	assert.False(t, drop.Confirmed, "nondeterministic noise must drop the finding")
}

// TestConfirmsResultByBodyDifferential_Legs pins which detection legs opt in.
func TestConfirmsResultByBodyDifferential_Legs(t *testing.T) {
	t.Parallel()
	mk := func(signal, detection string) *output.ResultEvent {
		r := &output.ResultEvent{Metadata: map[string]any{metaDetection: detection}}
		r.SetSignal(signal)
		return r
	}
	m := New()
	assert.True(t, m.ConfirmsResultByBodyDifferential(mk(output.SignalInband, detectionAuthBypass)))
	assert.True(t, m.ConfirmsResultByBodyDifferential(mk(output.SignalInband, detectionSizeChange)))
	assert.False(t, m.ConfirmsResultByBodyDifferential(mk(output.SignalInband, detectionBooleanDiff)),
		"the boolean leg's always-true response can equal the baseline")
	assert.False(t, m.ConfirmsResultByBodyDifferential(mk(output.SignalTiming, detectionTimeBased)),
		"a delay is not visible in a replayed body")
	assert.False(t, m.ConfirmsResultByBodyDifferential(&output.ResultEvent{}))
}
