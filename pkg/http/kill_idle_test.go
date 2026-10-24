package http

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/pkg/proxytarget"
	"github.com/vigolium/vigolium/pkg/types"
)

func TestKillIdleConns(t *testing.T) {
	pooled := &http.Transport{}
	cases := []struct {
		name string
		rt   http.RoundTripper
		want bool
	}{
		{"bare pooled transport", pooled, false},
		{"proxied pooled transport", proxytarget.Wrap(&http.Transport{Proxy: http.ProxyFromEnvironment}), false},
		{"keep-alives disabled", &http.Transport{DisableKeepAlives: true}, true},
		{"proxied keep-alives disabled", proxytarget.Wrap(&http.Transport{DisableKeepAlives: true}), true},
		{"unknown round tripper", roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil }), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := killIdleConns(tc.rt); got != tc.want {
				t.Errorf("killIdleConns = %v, want %v", got, tc.want)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestProxiedScanKeepsItsPool: behind --proxy the scan transport is wrapped in
// proxytarget.Transport, which hid it from retryablehttp's keep-alive check, so
// every client closed its idle pool after each 100 requests. Sequential
// requests through a keep-alive proxy must ride one proxy connection.
func TestProxiedScanKeepsItsPool(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(target.Close)

	var proxyConns atomic.Int64
	upstream := &http.Transport{}
	t.Cleanup(upstream.CloseIdleConnections)
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := r.Clone(r.Context())
		out.RequestURI = ""
		resp, err := upstream.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	proxy.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			proxyConns.Add(1)
		}
	}
	proxy.Start()
	t.Cleanup(proxy.Close)

	opts := types.DefaultOptions()
	opts.ProxyURL = proxy.URL
	r := newTestRequesterWithOpts(t, opts)

	addr := target.Listener.Addr().String()
	for i := 0; i < 250; i++ {
		if code := executeRecord(t, r, scanRecord(t, addr, "/p", addr)); code != http.StatusOK {
			t.Fatalf("request %d: status %d", i, code)
		}
	}
	if got := proxyConns.Load(); got != 1 {
		t.Errorf("proxy accepted %d connections for 250 sequential requests, want 1 (the pool was flushed)", got)
	}
}
