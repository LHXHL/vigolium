package ssrf_blind

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// PARTIAL: blind SSRF confirmation is purely out-of-band (Interactsh/OAST DNS or
// HTTP callback) and cannot be observed in-band with httptest. These tests cover
// construction, metadata, the no-OAST early-return path, and the pure
// URL-parameter heuristic; the asynchronous callback path is exercised by the
// OAST/canary harness instead.

// TestNew_Metadata verifies the module wires its identity, severity, and tags.
func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, severity.High, m.Severity())
	assert.Contains(t, m.Tags(), "ssrf")
}

// TestScanPerInsertionPoint_NoOAST ensures the scan is a no-op (no finding, no
// error) when no OAST provider is configured — the only path observable in-band.
func TestScanPerInsertionPoint_NoOAST(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/fetch?url=http://example.com")
	ip := modtest.InsertionPoint(t, rr, "url")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "without an OAST provider the blind SSRF module must not produce findings")
}

// TestLooksLikeURLParam exercises the pure URL-parameter heuristic by name and
// by value prefix.
func TestLooksLikeURLParam(t *testing.T) {
	t.Parallel()
	// Name-based matches.
	assert.True(t, looksLikeURLParam(httpmsg.INS_PARAM_URL, "redirect_url", "anything"))
	assert.True(t, looksLikeURLParam(httpmsg.INS_PARAM_URL, "callback", "x"))
	assert.True(t, looksLikeURLParam(httpmsg.INS_PARAM_URL, "proxy", "x"))
	// Value-based matches.
	assert.True(t, looksLikeURLParam(httpmsg.INS_PARAM_URL, "q", "http://internal/"))
	assert.True(t, looksLikeURLParam(httpmsg.INS_PARAM_URL, "q", "https://internal/"))
	assert.True(t, looksLikeURLParam(httpmsg.INS_PARAM_URL, "q", "//internal/"))
	// Neither name nor value suggests a URL.
	assert.False(t, looksLikeURLParam(httpmsg.INS_PARAM_URL, "q", "hello"))
	assert.False(t, looksLikeURLParam(httpmsg.INS_PARAM_URL, "count", "42"))
}

// recordingOAST is a fake OAST provider that records every planted payload.
type recordingOAST struct {
	payloads []string
}

func (f *recordingOAST) GenerateURL(_, _, _, _, _ string) string { return "ssrfnonce.oast.example" }
func (f *recordingOAST) RecordPayload(_, payload string)        { f.payloads = append(f.payloads, payload) }
func (f *recordingOAST) Enabled() bool                          { return true }

// TestScanPerInsertionPoint_BlindSSRFParamNames drives the real scan against a
// local server: blind-SSRF sink names (webhook, avatar, ?host=, nextUrl) get an
// OAST probe planted, while names that only contain a short token as a
// substring (ghost, context, token, timeout) are left alone.
func TestScanPerInsertionPoint_BlindSSRFParamNames(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	client := modtest.Requester(t)

	for _, name := range []string{"webhook", "avatar", "host", "returnTo", "feed"} {
		rr := modtest.Request(t, srv.URL+"/hooks?"+name+"=abc")
		ip := modtest.InsertionPoint(t, rr, name)
		oast := &recordingOAST{}
		_, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{OASTProvider: oast})
		require.NoError(t, err)
		assert.NotEmptyf(t, oast.payloads, "blind-SSRF sink %q must receive an OAST probe", name)
	}

	before := hits.Load()
	for _, name := range []string{"ghost", "context", "token", "timeout", "feedback"} {
		rr := modtest.Request(t, srv.URL+"/hooks?"+name+"=abc")
		ip := modtest.InsertionPoint(t, rr, name)
		oast := &recordingOAST{}
		_, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{OASTProvider: oast})
		require.NoError(t, err)
		assert.Emptyf(t, oast.payloads, "%q is not a URL sink and must not be probed", name)
	}
	assert.Equal(t, before, hits.Load(), "non-URL params must not send any request")
}
