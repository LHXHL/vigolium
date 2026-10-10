package cftbrowser

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"testing"
)

// fakeCfT serves a CfT version index and a zip holding a stub chrome binary
// (a shell script that answers --version), so EnsureBrowser runs end to end
// with no network beyond loopback. HOME is a temp dir, so the cache is too.
func fakeCfT(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" || !IsSupported() {
		t.Skip("needs a CfT platform with /bin/sh")
	}
	t.Setenv("HOME", t.TempDir())

	plat := platforms[runtime.GOOS+"_"+runtime.GOARCH]
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	bin, err := zw.CreateHeader(&zip.FileHeader{Name: plat.BinPath, Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = bin.Write([]byte("#!/bin/sh\necho 'Google Chrome for Testing 1.2.3'\n"))
	// Padding so the download spans several progress steps.
	pad, err := zw.CreateHeader(&zip.FileHeader{Name: "pad.bin", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = pad.Write(bytes.Repeat([]byte{0xAB}, 512*1024))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	archive := zbuf.Bytes()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/index.json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(apiResponse{Channels: map[string]channelInfo{
			"Stable": {Version: "1.2.3", Downloads: downloadSection{Chrome: []platformDownload{
				{Platform: plat.Key, URL: srv.URL + "/chrome.zip"},
			}}},
		}})
	})
	mux.HandleFunc("/chrome.zip", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(archive)))
		_, _ = w.Write(archive)
	})

	orig := apiURL
	apiURL = srv.URL + "/index.json"
	t.Cleanup(func() { apiURL = orig })
}

// TestEnsureBrowserReportsProgress: with a ProgressFunc the caller sees started,
// downloading steps with a known total, then finished carrying the archive size
// — and the text rendering stays off stderr.
func TestEnsureBrowserReportsProgress(t *testing.T) {
	fakeCfT(t)
	text := captureProgress(t)

	var events []ProgressEvent
	path, err := EnsureBrowser(context.Background(), func(ev ProgressEvent) { events = append(events, ev) })
	if err != nil {
		t.Fatalf("EnsureBrowser: %v", err)
	}
	if path == "" {
		t.Fatal("no binary path")
	}
	if len(events) < 3 {
		t.Fatalf("want started, downloading…, finished; got %+v", events)
	}
	if events[0].State != StateStarted {
		t.Errorf("first event = %q, want started", events[0].State)
	}
	last := events[len(events)-1]
	if last.State != StateFinished || last.Version != "1.2.3" || last.Bytes <= 512*1024 {
		t.Errorf("last event = %+v, want finished v1.2.3 with the archive size", last)
	}
	var downloading int
	for _, ev := range events[1 : len(events)-1] {
		if ev.State != StateDownloading {
			t.Errorf("middle event %+v is not downloading", ev)
			continue
		}
		downloading++
		if ev.Total <= 0 || ev.Bytes > ev.Total {
			t.Errorf("downloading event %+v lacks a sane total", ev)
		}
	}
	if downloading == 0 {
		t.Error("no downloading events")
	}
	if text.Len() != 0 {
		t.Errorf("text progress printed although a ProgressFunc was given: %q", text.String())
	}

	// Second call: cache hit, still exactly one started and one finished.
	events = nil
	if _, err := EnsureBrowser(context.Background(), func(ev ProgressEvent) { events = append(events, ev) }); err != nil {
		t.Fatalf("cached EnsureBrowser: %v", err)
	}
	if len(events) != 2 || events[0].State != StateStarted || events[1].State != StateFinished || events[1].Bytes != 0 {
		t.Errorf("cache hit events = %+v, want started + finished with no bytes", events)
	}
}

// TestEnsureBrowserReportsFailure: a failed download ends in exactly one failed
// event carrying the error.
func TestEnsureBrowserReportsFailure(t *testing.T) {
	fakeCfT(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	apiURL = srv.URL

	var events []ProgressEvent
	if _, err := EnsureBrowser(context.Background(), func(ev ProgressEvent) { events = append(events, ev) }); err == nil {
		t.Fatal("EnsureBrowser succeeded against a failing index")
	}
	if len(events) != 2 || events[1].State != StateFailed || events[1].Err == nil {
		t.Fatalf("events = %+v, want started + failed with an error", events)
	}
}
