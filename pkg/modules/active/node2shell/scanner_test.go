package node2shell

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	node2shellinfra "github.com/vigolium/vigolium/pkg/modules/infra/node2shell"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// decodeBrotli stands in for a real Brotli decoder.
//
// Nothing in this repo's dependency tree can decode the probe — the Go port
// carries the fix and refuses it (see the infra package's
// TestGoDecoderRejectsBothStreams) — so an affected decoder has to be
// simulated. The simulation is narrow on purpose: it recognizes the probe by
// its exact length and answers exactly what libbrotli 1.2.0 answers for it,
// and it refuses the twin the way every decoder does. Everything else goes to
// the real decoder.
func decodeBrotli(body []byte, affected bool) ([]byte, bool) {
	switch len(body) {
	case node2shellinfra.ProbeBytes:
		if !affected {
			return nil, false // a decoder with the fix refuses it
		}
		return node2shellinfra.DecodedProbe, true
	case node2shellinfra.TwinBytes:
		return nil, false // one repetition past the wrap: malformed for everyone
	}
	out, err := io.ReadAll(brotli.NewReader(bytes.NewReader(body)))
	return out, err == nil
}

// handleJSON is a JSON route handler: malformed JSON is 400, an object without
// name is 422. The probe decodes to "{}" plus spaces, so it lands on 422 —
// exactly where a plain {} body lands, which is the oracle.
func handleJSON(w http.ResponseWriter, body []byte) {
	var v map[string]any
	if err := json.Unmarshal(body, &v); err != nil {
		http.Error(w, `{"error":"invalid JSON: unexpected end of input"}`, http.StatusBadRequest)
		return
	}
	if _, ok := v["name"]; !ok {
		http.Error(w, `{"error":"field name is required"}`, http.StatusUnprocessableEntity)
		return
	}
	_, _ = w.Write([]byte(`{"ok":true}`))
}

type serverOpts struct {
	// affected makes the simulated Brotli decoder accept the probe.
	affected bool
	// global mounts the body parser on every route rather than only on /upload.
	global bool
	// dropAbove, when non-zero, replaces any body larger than it with "{}" —
	// the size-driven confound the twin exists to catch.
	dropAbove int
	// rejectAbove, when non-zero, answers 413 for any body larger than it.
	rejectAbove int
	// affectedProbes, when non-nil, overrides affected per probe delivery: the
	// Nth multi-MiB probe is decoded only if affectedProbes[N] is true. It
	// simulates a pool whose members disagree about the patch level.
	affectedProbes []bool
	// stackedOnly refuses plain br but accepts "gzip, br", the shape of a guard
	// that only inspects the first coding token.
	stackedOnly bool
	// beforeBody runs on every request and can answer it outright.
	beforeBody func(w http.ResponseWriter, r *http.Request) bool
}

// brotliApp mimics a body parser that knows br: an unknown encoding is 415
// before the body is read, a known one that fails to decode is 400.
func brotliApp(o serverOpts) http.Handler {
	var bigSeen atomic.Int64
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if o.beforeBody != nil && o.beforeBody(w, r) {
			return
		}
		if o.rejectAbove > 0 && len(raw) > o.rejectAbove {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		if o.global || r.URL.Path == "/upload" {
			enc := r.Header.Get("Content-Encoding")
			accepted := enc == "" || enc == "gzip" || enc == node2shellinfra.StackedEncoding ||
				(enc == "br" && !o.stackedOnly)
			if !accepted {
				http.Error(w, `UnsupportedMediaTypeError: unsupported content encoding "`+enc+`"`, http.StatusUnsupportedMediaType)
				return
			}
			if o.dropAbove > 0 && len(raw) > o.dropAbove {
				// The body never reaches the decoder: a buffering limit turned it
				// into an empty document.
				raw = []byte("{}")
			} else {
				affected := o.affected
				if len(raw) > 1<<20 && o.affectedProbes != nil {
					// A pool whose members disagree: each multi-MiB delivery is
					// answered by the next backend in the list.
					n := int(bigSeen.Add(1)) - 1
					affected = n < len(o.affectedProbes) && o.affectedProbes[n]
				}
				body, ok := modtest.DecodeContentEncoding(raw, enc, func(b []byte) ([]byte, bool) { return decodeBrotli(b, affected) })
				if !ok {
					http.Error(w, "Error: Decompression failed", http.StatusBadRequest)
					return
				}
				raw = body
			}
		}
		if !o.global && r.URL.Path != "/upload" {
			http.Error(w, "Cannot POST "+r.URL.Path, http.StatusNotFound)
			return
		}
		handleJSON(w, raw)
	})
}

// countingServer wraps h and records every request's body size, so a test can
// assert that no multi-MiB body was ever sent. len(*sizes) is the hit count.
func countingServer(t *testing.T, h http.Handler, sizes *[]int) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	return modtest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		n, _ := io.Copy(&buf, r.Body)
		mu.Lock()
		*sizes = append(*sizes, int(n))
		mu.Unlock()
		r.Body = io.NopCloser(&buf)
		h.ServeHTTP(w, r)
	}))
}

// An app-wide parser on an affected decoder: the probe reaches the route's {}
// class, the twin reaches its malformed class, and the result is a lead.
func TestScanPerHost_AffectedDecoder(t *testing.T) {
	t.Parallel()
	srv := modtest.Serve(t, brotliApp(serverOpts{affected: true, global: true}))

	rr := modtest.Request(t, srv.URL+"/")
	res, err := New().ScanPerHost(rr, modtest.Requester(t), modtest.ScanCtxWithTech(srv.URL, "nestjs"))
	require.NoError(t, err)
	require.Len(t, res, 1)

	r := res[0]
	assert.Equal(t, severity.Suspect, r.Info.Severity)
	assert.Equal(t, severity.Tentative, r.Info.Confidence)
	assert.Equal(t, output.RecordKindCandidate, r.RecordKind)
	assert.False(t, r.IsFinding(), "an unobservable decoder version stays a lead")
	assert.Equal(t, srv.URL+probePath, r.URL)
	assert.Contains(t, r.Info.Name, "CVE-2026-111497")
	assert.Contains(t, r.Info.Reference, "https://github.com/assetnote/node2shell-scanner")
	assert.Equal(t, "br", r.Metadata["encoding"])
	assert.Equal(t, node2shellinfra.LaneHost, r.Metadata["lane"])
	assert.Equal(t, true, r.Metadata["stable"])
	assert.Equal(t, "Node.js app (body parser)", r.Metadata["decoder"])

	joined := strings.Join(r.ExtractedResults, "\n")
	assert.Contains(t, joined, "Size-matched twin")
	assert.Contains(t, joined, "answered like a refused stream")
	assert.Contains(t, joined, "the route answered the tiny valid control as before")
}

// The evidence must never carry the probe body: a finding travels through the
// database, the JSON envelope and the report.
func TestEvidenceElidesTheProbeBody(t *testing.T) {
	t.Parallel()
	srv := modtest.Serve(t, brotliApp(serverOpts{affected: true, global: true}))

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), modtest.ScanCtxWithTech(srv.URL))
	require.NoError(t, err)
	require.Len(t, res, 1)

	r := res[0]
	assert.Less(t, len(r.Request), 4096, "the 22 MiB probe body must be elided from the request evidence")
	assert.Contains(t, r.Request, "more bytes of the probe body elided")
	assert.Contains(t, r.Request, "Content-Length: 23068764", "the framing a reader needs is kept")
	assert.Contains(t, r.Request, "Expect: 100-continue")
	for _, ev := range r.AdditionalEvidence {
		assert.Less(t, len(ev), 8192)
	}
}

// A decoder with the fix refuses the probe, so it lands in the malformed class
// and nothing is reported. This is the common case and the one that decides
// whether the module is usable.
func TestScanPerHost_PatchedDecoderIsSilent(t *testing.T) {
	t.Parallel()
	srv := modtest.Serve(t, brotliApp(serverOpts{affected: false, global: true}))

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), modtest.ScanCtxWithTech(srv.URL))
	require.NoError(t, err)
	assert.Empty(t, res)
}

// The improvement over the Assetnote scanner, whose controls are all one byte:
// a host that silently drops any multi-MiB body answers the probe with the
// route's {} class for a reason that has nothing to do with the decoder. The
// size-matched twin gets the same answer, so nothing is reported.
func TestScanPerHost_SizeDrivenAnswerIsNotReported(t *testing.T) {
	t.Parallel()
	srv := modtest.Serve(t, brotliApp(serverOpts{affected: true, global: true, dropAbove: 1 << 20}))

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), modtest.ScanCtxWithTech(srv.URL))
	require.NoError(t, err)
	assert.Empty(t, res, "the twin was answered like plain {} too: size, not the decode, moved the answer")
}

// An edge that refuses the advertised Content-Length never let the decoder see
// the stream, so the probe is inconclusive rather than negative.
func TestScanPerHost_RefusedBeforeDecode(t *testing.T) {
	t.Parallel()
	srv := modtest.Serve(t, brotliApp(serverOpts{affected: true, global: true, rejectAbove: 1 << 20}))

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), modtest.ScanCtxWithTech(srv.URL))
	require.NoError(t, err)
	assert.Empty(t, res)
}

// The cheap gate is what makes the module affordable: on a host that does not
// decode Brotli request bodies at all, not one multi-MiB body is sent.
func TestNoLargeUploadWithoutADecoder(t *testing.T) {
	t.Parallel()
	var sizes []int
	// A server that ignores Content-Encoding entirely, as Flask and FastAPI do.
	srv := countingServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		handleJSON(w, raw)
	}), &sizes)

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), modtest.ScanCtxWithTech(srv.URL))
	require.NoError(t, err)
	assert.Empty(t, res)

	require.NotEmpty(t, sizes, "the gate must actually have run")
	for i, n := range sizes {
		assert.Less(t, n, 1024, "request %d uploaded %d bytes before a decoder was proven", i, n)
	}
}

// A pool that mixes patched and unpatched backends answers the first probe
// like an affected decoder and the second like a fixed one. One round would
// call that vulnerable; two rounds do not.
func TestScanPerHost_MixedPoolNeedsEveryRound(t *testing.T) {
	t.Parallel()
	srv := modtest.Serve(t, brotliApp(serverOpts{
		global: true,
		// probe round 1 affected, twin (refused either way), probe round 2 not.
		affectedProbes: []bool{true, false, false},
	}))

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), modtest.ScanCtxWithTech(srv.URL))
	require.NoError(t, err)
	assert.Empty(t, res, "the second round landed on a backend that refused the probe")
}

// The mirror of the test above: every round must see the affected decoder for
// the lead to be filed, so a pool that is uniformly affected still reports.
func TestScanPerHost_EveryRoundAffectedStillReports(t *testing.T) {
	t.Parallel()
	srv := modtest.Serve(t, brotliApp(serverOpts{
		global:         true,
		affectedProbes: []bool{true, true, true, true},
	}))

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), modtest.ScanCtxWithTech(srv.URL))
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Contains(t, strings.Join(res[0].ExtractedResults, "\n"), "over 2 rounds")
}

// A guard that refuses plain br but passes "gzip, br" is real exposure, and
// the exposure module reports it — but the probe is a bare Brotli document
// with a fixed 66-byte output, so there is no stacked form of it to send.
// The gate must close rather than spend 22 MiB that can only come back
// negative and read as "patched".
func TestScanPerHost_StackedOnlyEncodingIsNotProbed(t *testing.T) {
	t.Parallel()
	var sizes []int
	srv := countingServer(t, brotliApp(serverOpts{affected: true, global: true, stackedOnly: true}), &sizes)

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), modtest.ScanCtxWithTech(srv.URL))
	require.NoError(t, err)
	assert.Empty(t, res)

	require.NotEmpty(t, sizes)
	for i, n := range sizes {
		assert.Less(t, n, 1024, "request %d uploaded %d bytes under an encoding the probe cannot use", i, n)
	}
}

// A route whose classes drift between the gate and the probe cannot score the
// probe. Here the route starts answering everything 200 once the first
// multi-MiB body has gone through, which the between-round re-verification
// catches.
func TestScanPerHost_ClassDriftAfterFirstProbeIsNotReported(t *testing.T) {
	t.Parallel()
	var bigSeen atomic.Int64
	srv := modtest.Serve(t, brotliApp(serverOpts{
		affected: true,
		global:   true,
		beforeBody: func(w http.ResponseWriter, r *http.Request) bool {
			if r.ContentLength > 1<<20 {
				bigSeen.Add(1)
				return false
			}
			if bigSeen.Load() > 0 {
				// Every tiny control now gets one page, so the three classes
				// the gate learned have collapsed into one.
				_, _ = w.Write([]byte(`{"status":"degraded"}`))
				return true
			}
			return false
		},
	}))

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), modtest.ScanCtxWithTech(srv.URL))
	require.NoError(t, err)
	assert.Empty(t, res, "the learned classes no longer describe the route")
}

// A route that answers the probe with something that is neither the {} class
// nor the decode-failure class says nothing either way.
func TestScanPerHost_ThirdClassIsNotReported(t *testing.T) {
	t.Parallel()
	srv := modtest.Serve(t, brotliApp(serverOpts{
		affected: true,
		global:   true,
		beforeBody: func(w http.ResponseWriter, r *http.Request) bool {
			if r.ContentLength > 1<<20 {
				http.Error(w, "upstream connect error", http.StatusBadGateway)
				return true
			}
			return false
		},
	}))

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), modtest.ScanCtxWithTech(srv.URL))
	require.NoError(t, err)
	assert.Empty(t, res)
}

// A parser mounted on one route is invisible to the unrouted probe; the
// recorded JSON request finds it.
func TestScanPerRequest_RouteScopedParser(t *testing.T) {
	t.Parallel()
	srv := modtest.Serve(t, brotliApp(serverOpts{affected: true}))
	sc := modtest.ScanCtxWithTech(srv.URL, "express")
	client := modtest.Requester(t)

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL+"/"), client, sc)
	require.NoError(t, err)
	assert.Empty(t, res, "the unrouted path answers 404 whatever the body")

	res, err = New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), client, sc)
	require.NoError(t, err)
	assert.Empty(t, res, "a GET record has no route parser to probe")

	res, err = New().ScanPerRequest(modtest.RequestJSON(t, srv.URL+"/upload", `{"name":"a"}`), client, sc)
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, srv.URL+"/upload", res[0].URL)
	assert.Equal(t, node2shellinfra.LaneRoute, res[0].Metadata["lane"])
}
