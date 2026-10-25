package modtest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// Serve starts an httptest server for h and closes it when the test ends.
//
// It lives here rather than in each module's test file because every scan
// method takes (record, requester, scanCtx) and so every module test needs the
// same two lines; copies of it had already started appearing per package.
func Serve(t testing.TB, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// ScanCtxWithTech returns a ScanContext whose tech registry marks srvURL's host
// with each tag, the way a *_fingerprint passive module would have during a
// real scan. Pass no tags for a context that has seen no fingerprint — the
// case a tech-gated module must still handle.
func ScanCtxWithTech(srvURL string, tags ...string) *modkit.ScanContext {
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}
	host := strings.TrimPrefix(strings.TrimPrefix(srvURL, "http://"), "https://")
	for _, tag := range tags {
		if tag != "" {
			sc.MarkTech(host, tag)
		}
	}
	return sc
}
