// Package networktest holds test helpers for transports built on
// pkg/core/network.
package networktest

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// ResumeServer starts a TLS server that closes every connection after one
// response, so each request is a new handshake, and records whether each
// handshake resumed a session. It is stopped at test cleanup.
func ResumeServer(t testing.TB) (url string, resumed func() []bool) {
	t.Helper()
	var (
		mu  sync.Mutex
		got []bool
	)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.TLS != nil && r.TLS.DidResume)
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	srv.Config.SetKeepAlivesEnabled(false)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL, func() []bool {
		mu.Lock()
		defer mu.Unlock()
		return append([]bool(nil), got...)
	}
}

// AssertResumes sends three GETs through client to a ResumeServer and fails
// unless the first did a full handshake and the second and third resumed.
func AssertResumes(t testing.TB, client *http.Client) {
	t.Helper()
	url, resumed := ResumeServer(t)
	for i := 0; i < 3; i++ {
		resp, err := client.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	CheckResumed(t, resumed())
}

// CheckResumed fails unless got is [false true true]: one full handshake,
// then two resumed sessions.
func CheckResumed(t testing.TB, got []bool) {
	t.Helper()
	if len(got) != 3 || got[0] || !got[1] || !got[2] {
		t.Errorf("handshakes resumed = %v, want [false true true]", got)
	}
}
