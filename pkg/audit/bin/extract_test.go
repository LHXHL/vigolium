package bin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/internal/helperblob"
)

// fakeHelper returns an executable-sized payload for the host platform, its
// zstd-compressed form and its pin.
func fakeHelper(t *testing.T) (raw, blob []byte, pin helperblob.Pin) {
	t.Helper()
	raw = bytes.Repeat([]byte("vigolium-audit-fake-helper\x00"), (minBinarySize/27)+64)
	copy(raw, synthHeader(runtime.GOOS, runtime.GOARCH))
	var buf bytes.Buffer
	if err := helperblob.Compress(&buf, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	pin = helperblob.Pin{
		SHA256:   hex.EncodeToString(sum[:]),
		Size:     int64(len(raw)),
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}
	return raw, buf.Bytes(), pin
}

// memSource serves a compressed helper from memory, like the embedded source.
type memSource struct {
	p    helperblob.Pin
	blob []byte
}

func (memSource) kind() string                   { return SourceEmbedded }
func (s memSource) pin() (helperblob.Pin, error) { return s.p, nil }
func (memSource) ready(helperblob.Pin) bool      { return true }
func (memSource) origin(helperblob.Pin) string   { return "memory" }
func (s memSource) open(context.Context, helperblob.Pin) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s.blob)), nil
}

func TestInstallCompressedRoundTrip(t *testing.T) {
	t.Setenv(CacheDirEnv, t.TempDir())
	raw, blob, pin := fakeHelper(t)

	path, err := install(context.Background(), memSource{p: pin, blob: blob})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if want := "vigolium-audit-" + pin.SHA256[:12]; filepath.Base(filepath.Dir(path)) != want {
		t.Errorf("cache dir %s is not keyed by the uncompressed sha (%s)", filepath.Dir(path), want)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("installed helper differs from the uncompressed bytes")
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm()&0o111 == 0 {
			t.Error("installed helper is not executable")
		}
	}
	// Second call is a cache hit: a source that cannot be opened must not be
	// touched.
	again, err := install(context.Background(), memSource{p: pin, blob: nil})
	if err != nil || again != path {
		t.Fatalf("cached install = %q, %v; want %q", again, err, path)
	}
}

func TestInstallPinMismatchIsHardError(t *testing.T) {
	t.Setenv(CacheDirEnv, t.TempDir())
	_, blob, pin := fakeHelper(t)
	wrong := pin
	wrong.SHA256 = strings.Repeat("cd", 32)

	_, err := install(context.Background(), memSource{p: wrong, blob: blob})
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("err = %v, want ErrChecksumMismatch", err)
	}
	for _, want := range []string{"expected sha256 " + wrong.SHA256, "got " + pin.SHA256} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	dst, _ := cachedBinaryPath(wrong)
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Errorf("helper installed despite mismatch (stat err=%v)", statErr)
	}
}

func TestInstallRefusesForeignPlatformPin(t *testing.T) {
	t.Setenv(CacheDirEnv, t.TempDir())
	_, blob, pin := fakeHelper(t)
	pin.Platform = "plan9/mips"
	_, err := install(context.Background(), memSource{p: pin, blob: blob})
	if !errors.Is(err, ErrBinaryPlatformMismatch) {
		t.Fatalf("err = %v, want ErrBinaryPlatformMismatch", err)
	}
}

// withExternal installs pin as this platform's external pin and points the
// download client at srv.
func withExternal(t *testing.T, pin helperblob.Pin, srv *httptest.Server) {
	t.Helper()
	oldPins, oldClient := externalPins, httpClient
	externalPins = map[string]helperblob.Pin{runtime.GOOS + "_" + runtime.GOARCH: pin}
	if srv != nil {
		httpClient = srv.Client()
		t.Setenv(BaseURLEnv, srv.URL+"/helpers/")
	}
	t.Setenv(CacheDirEnv, t.TempDir())
	t.Cleanup(func() { externalPins, httpClient = oldPins, oldClient })
}

func helperServer(t *testing.T, pin helperblob.Pin, blob []byte, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/helpers/"+assetName(pin) {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(blob)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDownloadVerifiesAndCaches(t *testing.T) {
	raw, blob, pin := fakeHelper(t)
	var hits atomic.Int32
	withExternal(t, pin, helperServer(t, pin, blob, &hits))

	src := downloadSource{}
	if !src.ready(pin) {
		t.Fatal("download source not ready with an https base URL")
	}
	path, err := install(context.Background(), src)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, raw) {
		t.Fatal("downloaded helper differs from the pinned bytes")
	}
	if _, err := install(context.Background(), src); err != nil {
		t.Fatalf("cached install: %v", err)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("server hit %d times, want 1 (second install must use the cache)", n)
	}
}

func TestDownloadPinMismatch(t *testing.T) {
	_, blob, pin := fakeHelper(t)
	wrong := pin
	wrong.SHA256 = strings.Repeat("ef", 32)
	var hits atomic.Int32
	// The server serves the real blob under the wrong pin's asset name.
	withExternal(t, wrong, helperServer(t, wrong, blob, &hits))

	_, err := install(context.Background(), downloadSource{})
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("err = %v, want ErrChecksumMismatch", err)
	}
	if !strings.Contains(err.Error(), wrong.SHA256) || !strings.Contains(err.Error(), pin.SHA256) {
		t.Errorf("error %q must name expected and actual sha256", err)
	}
}

func TestDownloadUnavailable(t *testing.T) {
	_, blob, pin := fakeHelper(t)

	t.Run("offline", func(t *testing.T) {
		var hits atomic.Int32
		srv := helperServer(t, pin, blob, &hits)
		withExternal(t, pin, srv)
		srv.Close()
		_, err := install(context.Background(), downloadSource{})
		if !errors.Is(err, ErrHelperUnavailable) || !strings.Contains(err.Error(), BinaryEnv) {
			t.Fatalf("err = %v, want ErrHelperUnavailable with a %s hint", err, BinaryEnv)
		}
	})
	t.Run("not found", func(t *testing.T) {
		var hits atomic.Int32
		other := pin
		other.SHA256 = strings.Repeat("01", 32)
		withExternal(t, pin, helperServer(t, other, blob, &hits))
		_, err := install(context.Background(), downloadSource{})
		if !errors.Is(err, ErrHelperUnavailable) || !strings.Contains(err.Error(), "HTTP 404") {
			t.Fatalf("err = %v, want ErrHelperUnavailable for HTTP 404", err)
		}
	})
	t.Run("no base url", func(t *testing.T) {
		withExternal(t, pin, nil)
		t.Setenv(BaseURLEnv, "")
		src := downloadSource{}
		if src.ready(pin) {
			t.Error("ready without a base URL")
		}
		if _, err := install(context.Background(), src); !errors.Is(err, ErrHelperUnavailable) {
			t.Fatalf("err = %v, want ErrHelperUnavailable", err)
		}
	})
	t.Run("plain http refused", func(t *testing.T) {
		withExternal(t, pin, nil)
		t.Setenv(BaseURLEnv, "http://127.0.0.1:1/helpers")
		if _, err := install(context.Background(), downloadSource{}); !errors.Is(err, ErrHelperUnavailable) || !strings.Contains(err.Error(), "https") {
			t.Fatalf("err = %v, want an https-only ErrHelperUnavailable", err)
		}
	})
	t.Run("no pin for platform", func(t *testing.T) {
		withExternal(t, pin, nil)
		externalPins = nil
		if _, err := install(context.Background(), downloadSource{}); !errors.Is(err, ErrBinaryMissing) {
			t.Fatalf("err = %v, want ErrBinaryMissing", err)
		}
	})
}

func TestBinaryOverride(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "vigolium-audit")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(BinaryEnv, exe)
	got, err := Path()
	if err != nil || got != exe {
		t.Fatalf("Path() = %q, %v; want the override %q", got, err, exe)
	}
	if !Available() {
		t.Error("Available() false with a valid override")
	}
	if st := Status(); st.Source != SourceOverride || !st.Cached || st.Err != nil {
		t.Errorf("Status() = %+v, want a usable override", st)
	}

	t.Setenv(BinaryEnv, filepath.Join(dir, "missing"))
	if _, err := Path(); err == nil {
		t.Error("Path() accepted a missing override")
	}
	if Available() {
		t.Error("Available() true for a missing override")
	}
}
