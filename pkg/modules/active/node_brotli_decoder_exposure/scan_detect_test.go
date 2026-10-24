package node_brotli_decoder_exposure

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
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// bodyParser mimics body-parser's encoding handling, the statuses observed on
// real Express 5.3 / body-parser 2.4, Express 4.22 / body-parser 1.20 and
// NestJS 11: an unknown encoding is 415 before the body is read; a known one
// whose bytes fail to decode is 400.
func bodyParser(supportsBrotli bool) func(w http.ResponseWriter, r *http.Request) bool {
	return func(w http.ResponseWriter, r *http.Request) bool {
		switch enc := r.Header.Get("Content-Encoding"); enc {
		case "", "identity":
			return false
		case "br":
			if supportsBrotli {
				http.Error(w, "Error: Decompression failed", http.StatusBadRequest)
				return true
			}
			fallthrough
		default:
			http.Error(w, `UnsupportedMediaTypeError: unsupported content encoding "`+enc+`"`, http.StatusUnsupportedMediaType)
			return true
		}
	}
}

// expressApp serves POST /upload. With global set the parser runs on every
// route (NestJS, app.use(express.json())); otherwise only on /upload.
func expressApp(t *testing.T, supportsBrotli, global bool, hits *int64) *httptest.Server {
	t.Helper()
	parse := bodyParser(supportsBrotli)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(hits, 1)
		_, _ = io.Copy(io.Discard, r.Body)
		if (global || r.URL.Path == "/upload") && parse(w, r) {
			return
		}
		if r.URL.Path != "/upload" {
			http.Error(w, "Cannot POST "+r.URL.Path, http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte("DONE"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func nodeScanCtx(srvURL, tag string) *modkit.ScanContext {
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}
	if tag != "" {
		sc.MarkTech(strings.TrimPrefix(srvURL, "http://"), tag)
	}
	return sc
}

func TestScanPerRequest_AppWideParser(t *testing.T) {
	t.Parallel()
	var hits int64
	srv := expressApp(t, true, true, &hits)

	rr := modtest.Request(t, srv.URL+"/")
	res, err := New().ScanPerRequest(rr, modtest.Requester(t), nodeScanCtx(srv.URL, "nestjs"))
	require.NoError(t, err)
	require.Len(t, res, 1)

	r := res[0]
	assert.Equal(t, severity.Info, r.Info.Severity)
	assert.Equal(t, srv.URL+probePath, r.URL)
	assert.Contains(t, r.Info.Name, "CVE-2026-111497")
	assert.Contains(t, r.Request, "Content-Encoding: br")
	assert.Contains(t, r.AdditionalEvidence[0], "Content-Encoding: "+unknownEncoding)
	assert.EqualValues(t, 2, atomic.LoadInt64(&hits))
}

// A parser mounted on one route is invisible to the random-path probe; the
// recorded body-carrying request finds it.
func TestScanPerRequest_RouteScopedParser(t *testing.T) {
	t.Parallel()
	var hits int64
	srv := expressApp(t, true, false, &hits)
	sc := nodeScanCtx(srv.URL, "express")
	client := modtest.Requester(t)

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), client, sc)
	require.NoError(t, err)
	assert.Empty(t, res, "a GET record has no route parser to probe")

	res, err = New().ScanPerRequest(modtest.RequestJSON(t, srv.URL+"/upload", `{"a":1}`), client, sc)
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, srv.URL+"/upload", res[0].URL)
	assert.Equal(t, "route body parser", res[0].Metadata["lane"])
}

// body-parser 1.x (Express 4) refuses br like any unknown encoding: no finding.
func TestScanPerRequest_NoBrotliSupport(t *testing.T) {
	t.Parallel()
	var hits int64
	srv := expressApp(t, false, true, &hits)

	rr := modtest.RequestJSON(t, srv.URL+"/upload", `{"a":1}`)
	res, err := New().ScanPerRequest(rr, modtest.Requester(t), nodeScanCtx(srv.URL, "express"))
	require.NoError(t, err)
	assert.Empty(t, res)
}

// The gate fails closed: an unmarked host, or one marked only "nodejs" (as the
// Next/Nuxt fingerprints do), gets no request.
func TestScanPerRequest_GateFailsClosed(t *testing.T) {
	t.Parallel()
	for _, tag := range []string{"", "nodejs"} {
		var hits int64
		srv := expressApp(t, true, true, &hits)
		rr := modtest.RequestJSON(t, srv.URL+"/upload", `{"a":1}`)
		res, err := New().ScanPerRequest(rr, modtest.Requester(t), nodeScanCtx(srv.URL, tag))
		require.NoError(t, err)
		assert.Empty(t, res, "tag %q", tag)
		assert.Zero(t, atomic.LoadInt64(&hits), "tag %q", tag)
	}
}

func TestCarriesParsedBody(t *testing.T) {
	t.Parallel()
	assert.True(t, carriesParsedBody("POST", "application/json; charset=utf-8"))
	assert.True(t, carriesParsedBody("PUT", "application/vnd.api+json"))
	assert.True(t, carriesParsedBody("PATCH", "application/x-www-form-urlencoded"))
	assert.False(t, carriesParsedBody("GET", "application/json"))
	assert.False(t, carriesParsedBody("POST", "multipart/form-data; boundary=x"))
	assert.False(t, carriesParsedBody("POST", ""))
}
