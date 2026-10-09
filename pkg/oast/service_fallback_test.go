package oast

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
)

// fakeInteractshServer answers registration over plain HTTP, the way a host
// listening on port 80 would answer interactsh's cleartext retry. It counts the
// /register requests that reach it.
func fakeInteractshServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var registrations atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/register" {
			registrations.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"registration successful"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &registrations
}

// TestNew_NoCleartextRegistrationFallback: a server_url without a scheme is
// registered over https. When https fails, interactsh used to retry over
// cleartext http and send the registration secret in the clear; that retry must
// not happen unless the operator wrote http:// themselves.
func TestNew_NoCleartextRegistrationFallback(t *testing.T) {
	srv, registrations := fakeInteractshServer(t)
	host := strings.TrimPrefix(srv.URL, "http://")

	svc, err := New(&config.OASTConfig{Enabled: true, ServerURL: host}, nil, nil, "", "", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(svc.Close)
	if err := svc.WaitReady(context.Background(), 5*time.Second); err == nil {
		t.Fatal("OAST registered with a schemeless server_url over a plain-http server: the cleartext fallback is still on")
	}
	if svc.Enabled() {
		t.Error("Enabled() = true after a failed registration")
	}
	if n := registrations.Load(); n != 0 {
		t.Errorf("cleartext /register requests = %d, want 0", n)
	}
}

// TestNew_ExplicitHTTPServerStillRegisters: an explicit http:// server_url is
// the operator choosing cleartext, and keeps working.
func TestNew_ExplicitHTTPServerStillRegisters(t *testing.T) {
	srv, registrations := fakeInteractshServer(t)

	svc, err := New(&config.OASTConfig{Enabled: true, ServerURL: srv.URL}, nil, nil, "", "", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := svc.WaitReady(context.Background(), 5*time.Second); err != nil {
		svc.Close()
		t.Fatalf("OAST failed to register against an explicit http:// server_url: %v", err)
	}
	svc.Close()
	if n := registrations.Load(); n != 1 {
		t.Errorf("/register requests = %d, want 1", n)
	}
}

func TestExplicitCleartextServer(t *testing.T) {
	for in, want := range map[string]bool{
		"oast.pro":            false,
		"https://oast.pro":    false,
		"http://oast.example": true,
		"HTTP://oast.example": true,
		"http:/":              false,
		"":                    false,
	} {
		if got := explicitCleartextServer(in); got != want {
			t.Errorf("explicitCleartextServer(%q) = %v, want %v", in, got, want)
		}
	}
}
