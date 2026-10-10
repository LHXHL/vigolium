package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

// withPipedStdin points os.Stdin at the read end of a fresh pipe for the test
// and returns the write end. A pipe is a FIFO, so fileutil.HasStdin reports it
// as piped — the inherited-pipe shape these tests are about.
func withPipedStdin(t *testing.T) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = old
		_ = r.Close()
		_ = w.Close()
	})
	return w
}

func shortStdinWindows(t *testing.T, firstByte, total time.Duration) {
	t.Helper()
	oldWait, oldTimeout := implicitStdinWait, globalInputReadTimeout
	implicitStdinWait, globalInputReadTimeout = firstByte, total
	t.Cleanup(func() { implicitStdinWait, globalInputReadTimeout = oldWait, oldTimeout })
}

// A pipe the parent never writes to is "not piped", not an error and not a hang.
func TestReadStdinIfPipedSilentPipeIsNotPiped(t *testing.T) {
	_ = withPipedStdin(t)
	shortStdinWindows(t, 200*time.Millisecond, time.Minute)

	start := time.Now()
	data, ok, err := readStdinIfPiped()
	if err != nil || ok || data != "" {
		t.Fatalf("readStdinIfPiped() = (%q, %v, %v), want (\"\", false, nil)", data, ok, err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("took %s; a silent pipe must give up after the first-byte window", elapsed)
	}
}

func TestReadStdinIfPipedReadsData(t *testing.T) {
	w := withPipedStdin(t)
	shortStdinWindows(t, time.Second, time.Second)
	go func() {
		_, _ = w.WriteString("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")
		_ = w.Close()
	}()

	data, ok, err := readStdinIfPiped()
	if err != nil || !ok {
		t.Fatalf("readStdinIfPiped() = (%q, %v, %v)", data, ok, err)
	}
	if !strings.HasPrefix(data, "GET / HTTP/1.1") || strings.HasSuffix(data, "\n") {
		t.Errorf("data = %q, want the request with trailing newlines trimmed", data)
	}
}

// A producer that starts and then stalls is a real failure. It used to be
// swallowed into "no target", which sent the caller after the wrong problem.
func TestReadStdinIfPipedPropagatesAStall(t *testing.T) {
	w := withPipedStdin(t)
	shortStdinWindows(t, time.Second, 150*time.Millisecond)
	go func() { _, _ = w.WriteString("partial") }()

	_, ok, err := readStdinIfPiped()
	if ok || !errors.Is(err, clicommon.ErrStdinTimeout) {
		t.Fatalf("readStdinIfPiped() ok=%v err=%v, want an error wrapping ErrStdinTimeout", ok, err)
	}
}

func TestScanURLInputsSilentPipeIsAUsageError(t *testing.T) {
	_ = withPipedStdin(t)
	shortStdinWindows(t, 100*time.Millisecond, time.Minute)
	saveTargets := globalTargets
	globalTargets = nil
	t.Cleanup(func() { globalTargets = saveTargets })

	_, err := scanURLInputs(nil)
	if err == nil || classifyExitCode(err) != 2 {
		t.Fatalf("err = %v, want a usage error", err)
	}
	if !strings.Contains(err.Error(), "-t <url>") {
		t.Errorf("the message must name the ways to pass a target, got %q", err)
	}
}

func TestScanRequestStdin(t *testing.T) {
	t.Run("default -i on a silent pipe fails fast", func(t *testing.T) {
		_ = withPipedStdin(t)
		shortStdinWindows(t, 100*time.Millisecond, time.Minute)
		_, err := readScanRequestStdin(false)
		if err == nil || classifyExitCode(err) != 2 {
			t.Fatalf("err = %v, want a usage error", err)
		}
		if !strings.Contains(err.Error(), "-i -") {
			t.Errorf("the message must point at -i - for a slow producer, got %q", err)
		}
	})
	t.Run("typed -i - waits past the first-byte window", func(t *testing.T) {
		w := withPipedStdin(t)
		shortStdinWindows(t, 50*time.Millisecond, 5*time.Second)
		go func() {
			time.Sleep(300 * time.Millisecond)
			_, _ = w.WriteString("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")
			_ = w.Close()
		}()
		raw, err := readScanRequestStdin(true)
		if err != nil || !strings.HasPrefix(string(raw), "GET /") {
			t.Fatalf("readScanRequestStdin(true) = (%q, %v)", raw, err)
		}
	})
	t.Run("default -i with a terminal stdin fails fast", func(t *testing.T) {
		tty, err := os.Open("/dev/null") // a character device, like a terminal
		if err != nil {
			t.Skip("no /dev/null")
		}
		old := os.Stdin
		os.Stdin = tty
		t.Cleanup(func() { os.Stdin = old; _ = tty.Close() })
		_, err = readScanRequestStdin(false)
		if err == nil || classifyExitCode(err) != 2 {
			t.Fatalf("err = %v, want a usage error", err)
		}
	})
}

// The input layer's "no input" errors used to name -u and -l, flags vigolium
// has never had. Pin them out of every non-test source file under pkg/input.
func TestInputErrorsNameRealFlags(t *testing.T) {
	root := filepath.Join("..", "input")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, bad := range []string{"(-u)", "(-l)"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s mentions %s, which is not a vigolium flag", path, bad)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
