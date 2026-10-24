package php2shell

import (
	"bytes"
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
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// phpServer fakes a PHP endpoint: a body under 1 KiB is the control and gets
// "ok"; anything larger is a probe and gets onProbe's answer.
func phpServer(t *testing.T, poweredBy string, onProbe func(w http.ResponseWriter), hits *int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(hits, 1)
		n, _ := io.Copy(io.Discard, r.Body)
		if poweredBy != "" {
			w.Header().Set("X-Powered-By", poweredBy)
		}
		if n < 1024 {
			_, _ = w.Write([]byte("ok"))
			return
		}
		onProbe(w)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func phpScanCtx(t *testing.T, srvURL string) *modkit.ScanContext {
	t.Helper()
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}
	sc.MarkTech(strings.TrimPrefix(srvURL, "http://"), phpTechTag)
	return sc
}

func TestScanPerRequest_MemoryExhaustedIsSuspect(t *testing.T) {
	t.Parallel()
	var hits int64
	srv := phpServer(t, "", func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0"))
	}, &hits)

	rr := modtest.Request(t, srv.URL+"/")
	res, err := New().ScanPerRequest(rr, modtest.Requester(t), phpScanCtx(t, srv.URL))
	require.NoError(t, err)
	require.Len(t, res, 1)

	r := res[0]
	assert.Equal(t, severity.Suspect, r.Info.Severity)
	assert.Equal(t, severity.Tentative, r.Info.Confidence)
	assert.Equal(t, srv.URL+defaultPath, r.URL)
	assert.Contains(t, r.Info.Name, "CVE-2026-109618")
	assert.EqualValues(t, 2, atomic.LoadInt64(&hits), "control + the first (1 MiB) probe, then stop")
	assert.Less(t, len(r.Request), 8*1024, "the probe body must be elided from stored evidence")
	assert.Contains(t, r.Request, "multipart/form-data; boundary=")
	assert.Contains(t, r.Request, "more bytes of the multipart probe elided")
}

func TestScanPerRequest_EmptyFPMResponseIsSuspect(t *testing.T) {
	t.Parallel()
	var hits int64
	srv := phpServer(t, "PHP/8.3.20", func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadGateway)
	}, &hits)

	rr := modtest.Request(t, srv.URL+"/app/login.php?x=1")
	res, err := New().ScanPerRequest(rr, modtest.Requester(t), phpScanCtx(t, srv.URL))
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, srv.URL+"/app/login.php", res[0].URL, "a .php record path is probed in place")
	assert.Equal(t, "PHP-FPM", res[0].Metadata["sapi"])
	assert.Contains(t, strings.Join(res[0].ExtractedResults, "\n"), "predates the fix (8.3.36)")
}

// The gate fails closed: a host no PHP fingerprint marked gets no request.
func TestScanPerRequest_UnmarkedHostSendsNothing(t *testing.T) {
	t.Parallel()
	var hits int64
	srv := phpServer(t, "", func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) }, &hits)

	rr := modtest.Request(t, srv.URL+"/")
	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{TechStack: modkit.NewTechRegistry()})
	require.NoError(t, err)
	assert.Empty(t, res)
	assert.Zero(t, atomic.LoadInt64(&hits))
}

// A patched release advertised on the control stops before any probe.
func TestScanPerRequest_PatchedVersionSkipsProbes(t *testing.T) {
	t.Parallel()
	var hits int64
	srv := phpServer(t, "PHP/8.4.27", func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) }, &hits)

	rr := modtest.Request(t, srv.URL+"/")
	res, err := New().ScanPerRequest(rr, modtest.Requester(t), phpScanCtx(t, srv.URL))
	require.NoError(t, err)
	assert.Empty(t, res)
	assert.EqualValues(t, 1, atomic.LoadInt64(&hits), "only the control request")
}

// A non-empty 500 without the PHP fatal-error text is an application error,
// and a size refusal is inconclusive: neither is reported.
func TestScanPerRequest_NoSignal(t *testing.T) {
	t.Parallel()
	for name, onProbe := range map[string]func(http.ResponseWriter){
		"app error": func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Something went wrong"))
		},
		"too large": func(w http.ResponseWriter) { w.WriteHeader(http.StatusRequestEntityTooLarge) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var hits int64
			srv := phpServer(t, "", onProbe, &hits)
			rr := modtest.Request(t, srv.URL+"/")
			res, err := New().ScanPerRequest(rr, modtest.Requester(t), phpScanCtx(t, srv.URL))
			require.NoError(t, err)
			assert.Empty(t, res)
		})
	}
}

func TestBuildProbeBody(t *testing.T) {
	t.Parallel()
	body := buildProbeBody(1, 4000)
	assert.InDelta(t, 1<<20, len(body), 4)
	assert.True(t, bytes.HasPrefix(body, []byte("--\nx:\n")))
	assert.Equal(t, 4000, bytes.Count(body, []byte("name=a[]"+strings.Repeat("[a]", nestedKeys)+";")))
}
