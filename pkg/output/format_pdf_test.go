package output

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fakePDFHost(goos string, euid int, files map[string]bool, env map[string]string) pdfHost {
	return pdfHost{
		goos:   goos,
		euid:   euid,
		exists: func(p string) bool { return files[p] },
		getenv: func(k string) string { return env[k] },
	}
}

func TestPDFNoSandboxDecision(t *testing.T) {
	tests := []struct {
		name   string
		host   pdfHost
		want   bool
		reason string
	}{
		{"linux user", fakePDFHost("linux", 1000, nil, nil), false, ""},
		{"linux root", fakePDFHost("linux", 0, nil, nil), true, "running as root"},
		{"docker", fakePDFHost("linux", 1000, map[string]bool{"/.dockerenv": true}, nil), true, "running in a container"},
		{"podman", fakePDFHost("linux", 1000, map[string]bool{"/run/.containerenv": true}, nil), true, "running in a container"},
		{"kubernetes", fakePDFHost("linux", 1000, nil, map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1"}), true, "running in a container"},
		{"env opt-out", fakePDFHost("darwin", 501, nil, map[string]string{"VIGOLIUM_CHROME_NO_SANDBOX": "1"}), true, "VIGOLIUM_CHROME_NO_SANDBOX=1"},
		{"env zero keeps sandbox", fakePDFHost("linux", 1000, nil, map[string]string{"VIGOLIUM_CHROME_NO_SANDBOX": "0"}), false, ""},
		{"macos root keeps sandbox", fakePDFHost("darwin", 0, nil, nil), false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, why := pdfNoSandbox(tt.host)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.reason, why)
		})
	}
}

func TestPDFChromeArgs(t *testing.T) {
	base := pdfChromeParams{UserDataDir: "/tmp/p/profile", OutputPath: "/out/r.pdf", HTMLPath: "/tmp/p/report.html"}
	tests := []struct {
		name      string
		noSandbox bool
	}{
		{"sandboxed (non-root)", false},
		{"unsandboxed (root/container)", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := base
			p.NoSandbox = tt.noSandbox
			args := pdfChromeArgs(p)
			assert.Equal(t, tt.noSandbox, slices.Contains(args, "--no-sandbox"))
			assert.Contains(t, args, "--headless")
			assert.Contains(t, args, "--user-data-dir=/tmp/p/profile")
			assert.Contains(t, args, "--print-to-pdf=/out/r.pdf")
			assert.Equal(t, "file:///tmp/p/report.html", args[len(args)-1], "the page URL is the last argument")
		})
	}
}

func TestResolvePDFTimeout(t *testing.T) {
	env := func(v string) func(string) string { return func(string) string { return v } }
	assert.Equal(t, 5*time.Second, resolvePDFTimeout(5*time.Second, env("1m")), "explicit wins")
	assert.Equal(t, time.Minute, resolvePDFTimeout(0, env("1m")))
	assert.Equal(t, DefaultPDFTimeout, resolvePDFTimeout(0, env("")))
	assert.Equal(t, DefaultPDFTimeout, resolvePDFTimeout(0, env("garbage")))
	assert.Equal(t, DefaultPDFTimeout, resolvePDFTimeout(0, env("-3s")))
}

func writeFakeChrome(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake chrome is a shell script")
	}
	path := filepath.Join(t.TempDir(), "chrome")
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755))
	return path
}

// A Chrome that never finishes must not hang the export: the run is killed at
// the timeout (with its children, via the process group) and the error says so.
func TestRunPDFChromeTimeout(t *testing.T) {
	// The background sleep stands in for a renderer child holding stderr open.
	chrome := writeFakeChrome(t, "echo 'starting' >&2\nsleep 30 &\nsleep 30\n")
	start := time.Now()
	err := runPDFChrome(context.Background(), chrome, nil, filepath.Join(t.TempDir(), "r.pdf"), 300*time.Millisecond)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second, "timeout must kill the process group promptly")
	assert.True(t, errors.Is(err, ErrPDFFailed))
	assert.Contains(t, err.Error(), "did not finish within 300ms")
	assert.Contains(t, err.Error(), "starting", "stderr tail carried into the error")
}

func TestRunPDFChromeFailureCarriesStderrTail(t *testing.T) {
	chrome := writeFakeChrome(t, "i=0\nwhile [ $i -lt 2000 ]; do echo \"noise line $i\" >&2; i=$((i+1)); done\necho 'FATAL: missing libnss3.so' >&2\nexit 3\n")
	err := runPDFChrome(context.Background(), chrome, nil, filepath.Join(t.TempDir(), "r.pdf"), 10*time.Second)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPDFFailed))
	msg := err.Error()
	assert.Contains(t, msg, "FATAL: missing libnss3.so")
	assert.NotContains(t, msg, "noise line 0\n", "only the tail is kept")
	assert.Less(t, len(msg), pdfStderrTailBytes+512)
}

func TestRunPDFChromeSuccess(t *testing.T) {
	out := filepath.Join(t.TempDir(), "r.pdf")
	chrome := writeFakeChrome(t, "printf '%%PDF-1.4' > \"$1\"\nexit 0\n")
	require.NoError(t, runPDFChrome(context.Background(), chrome, []string{out}, out, 10*time.Second))
}

func TestRunPDFChromeCleanExitWithoutOutputFails(t *testing.T) {
	chrome := writeFakeChrome(t, "exit 0\n")
	err := runPDFChrome(context.Background(), chrome, nil, filepath.Join(t.TempDir(), "r.pdf"), 10*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "without writing the PDF")
}

// Chrome that writes the PDF and then wedges (or fails) in teardown still
// produced the document: the export succeeds after a short grace instead of
// waiting out the whole timeout.
func TestRunPDFChromeTeardownHangAfterWrite(t *testing.T) {
	old := pdfTeardownGrace
	pdfTeardownGrace = 200 * time.Millisecond
	t.Cleanup(func() { pdfTeardownGrace = old })

	out := filepath.Join(t.TempDir(), "r.pdf")
	chrome := writeFakeChrome(t, "printf '%%PDF-1.4' > \"$1\"\necho \"8 bytes written to file $1\" >&2\nsleep 30\n")
	start := time.Now()
	require.NoError(t, runPDFChrome(context.Background(), chrome, []string{out}, out, 20*time.Second))
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestRunPDFChromeNonZeroExitAfterWrite(t *testing.T) {
	out := filepath.Join(t.TempDir(), "r.pdf")
	chrome := writeFakeChrome(t, "printf '%%PDF-1.4' > \"$1\"\necho \"8 bytes written to file $1\" >&2\necho 'Teardown watchdog expired' >&2\nexit 2\n")
	require.NoError(t, runPDFChrome(context.Background(), chrome, []string{out}, out, 10*time.Second))
}

func TestTailBufferKeepsLastBytes(t *testing.T) {
	tb := &tailBuffer{max: 8}
	_, _ = tb.Write([]byte("abcdef"))
	_, _ = tb.Write([]byte("ghij"))
	assert.Equal(t, "cdefghij", tb.String())
	_, _ = tb.Write([]byte(strings.Repeat("z", 20)))
	assert.Equal(t, "zzzzzzzz", tb.String())
	tb2 := &tailBuffer{max: 4}
	_, _ = tb2.Write([]byte("xé日")) // the cut lands inside a multibyte rune
	assert.Equal(t, "日", tb2.String())
}
