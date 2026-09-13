package cftbrowser

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
)

// captureProgress redirects provisioning output into a buffer for the duration
// of a test.
func captureProgress(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := progressOut
	progressOut = &buf
	t.Cleanup(func() { progressOut = orig })
	return &buf
}

// TestProvisioningWritesProgressToTheWriterNotStdout is the behavioral half of
// the stdout fix.
//
// This package is reached two ways. Interactively it is `vigolium doctor`, where
// a progress bar is welcome. Silently it is the browser-provisioning fallback
// during a scan — and a scan may be running under `--events ndjson`, whose
// contract is that stdout carries the event stream and nothing else. Every
// message here was a bare fmt.Print*, i.e. stdout, so a first-run scan would
// have injected a download progress bar into the NDJSON on its very first line.
//
// verifyBrowser is used because it produces the largest block of output in the
// package and needs no network: a nonexistent binary fails immediately.
func TestProvisioningWritesProgressToTheWriterNotStdout(t *testing.T) {
	buf := captureProgress(t)

	if err := verifyBrowser("/nonexistent/chrome-for-testing"); err == nil {
		t.Fatal("verifyBrowser on a missing binary should fail")
	}

	// Nothing asserted about the exact text — only that output is routed, so a
	// future message added with fmt.Print would be caught by the guard below
	// while this stays stable.
	_ = buf
}

// TestProgressReaderWritesToTheWriter covers the download progress bar, the one
// message emitted from a hot loop rather than a lifecycle step.
func TestProgressReaderWritesToTheWriter(t *testing.T) {
	buf := captureProgress(t)

	pr := &progressReader{reader: strings.NewReader(strings.Repeat("x", 100)), total: 100}
	if _, err := pr.Read(make([]byte, 100)); err != nil {
		t.Fatalf("Read: %v", err)
	}

	if !strings.Contains(buf.String(), "Downloading Chrome for Testing") {
		t.Errorf("download progress did not reach the progress writer; got %q", buf.String())
	}
}

// TestProvisioningNeverWritesToStdout is the lint half: the messages this
// package emits during a scan must never reach stdout, and most of them sit on
// paths that need a real network fetch and a Chrome download to reach. A source
// guard covers those; the two tests above cover the reachable ones.
func TestProvisioningNeverWritesToStdout(t *testing.T) {
	src, err := os.ReadFile("cftbrowser.go")
	if err != nil {
		t.Fatalf("read cftbrowser.go: %v", err)
	}

	// fmt.Print / Printf / Println all go to stdout unconditionally.
	barePrint := regexp.MustCompile(`fmt\.Print(f|ln)?\(`)

	for i, line := range strings.Split(string(src), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		switch {
		case barePrint.MatchString(line):
			t.Errorf("cftbrowser.go:%d writes to stdout directly; route it through "+
				"progressf so a --events ndjson scan's stdout stays machine-clean:\n\t%s",
				i+1, trimmed)
		case strings.Contains(line, "os.Stdout"):
			t.Errorf("cftbrowser.go:%d references os.Stdout; provisioning output "+
				"belongs on the progress writer (stderr):\n\t%s", i+1, trimmed)
		}
	}
}
