package output

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/internal/scratch"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/utils"

	"github.com/go-rod/rod/lib/launcher"
	"go.uber.org/zap"
)

// DefaultPDFTimeout bounds one headless-Chrome PDF render. A wedged Chrome
// (a missing display library, a stuck GPU process, a sandbox prompt) would
// otherwise hang the export forever.
const DefaultPDFTimeout = 90 * time.Second

// pdfStderrTailBytes is how much of Chrome's stderr a failure carries back.
// The tail is where the fatal line lands; the head is allocator chatter.
const pdfStderrTailBytes = 4096

// ErrPDFFailed marks every PDF-export failure. It carries the pdf_failed error
// code (Code()), so the CLI's error classifier and a REST handler report it
// without matching on text; errors.Is(err, ErrPDFFailed) still works.
var ErrPDFFailed error = pdfFailedError{}

type pdfFailedError struct{}

func (pdfFailedError) Error() string               { return "pdf export failed" }
func (pdfFailedError) Code() apicontract.ErrorCode { return apicontract.CodePDFFailed }

// GeneratePDFReport renders the report as HTML and prints it to PDF with
// headless Chrome. It keeps the shared report-generator signature; use
// GeneratePDFReportContext to bound or cancel the render from a caller context.
func GeneratePDFReport(items []any, outputPath string, meta HTMLReportMeta) error {
	return GeneratePDFReportContext(context.Background(), items, outputPath, meta)
}

// GeneratePDFReportContext is GeneratePDFReport with cancellation. The render
// is additionally bounded by meta.PDFTimeout (VIGOLIUM_PDF_TIMEOUT, else
// DefaultPDFTimeout); on timeout or cancel the whole Chrome process group is
// killed. Chrome runs with a throwaway --user-data-dir that is removed
// afterwards, and --no-sandbox only where the sandbox cannot work (root, a
// container) or when VIGOLIUM_CHROME_NO_SANDBOX=1.
func GeneratePDFReportContext(ctx context.Context, items []any, outputPath string, meta HTMLReportMeta) error {
	chromePath, found := launcher.LookPath()
	if !found {
		return fmt.Errorf("%w: Chrome/Chromium not found; install Google Chrome or Chromium to export PDF", ErrPDFFailed)
	}

	tmpDir, err := scratch.MkdirTemp("pdf-*")
	if err != nil {
		return fmt.Errorf("%w: failed to create temp directory: %w", ErrPDFFailed, err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	htmlPath := filepath.Join(tmpDir, "report.html")
	if err := GenerateDocumentReport(items, htmlPath, meta); err != nil {
		return fmt.Errorf("%w: failed to generate HTML for PDF: %w", ErrPDFFailed, err)
	}

	absOutput, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("%w: failed to resolve output path: %w", ErrPDFFailed, err)
	}

	noSandbox, why := pdfNoSandbox(currentPDFHost())
	if noSandbox {
		zap.L().Info("PDF export: Chrome sandbox disabled", zap.String("reason", why))
	}
	args := pdfChromeArgs(pdfChromeParams{
		UserDataDir: filepath.Join(tmpDir, "profile"),
		OutputPath:  absOutput,
		HTMLPath:    htmlPath,
		NoSandbox:   noSandbox,
	})

	// A stale file from an earlier export must not pass for this run's output.
	if err := os.Remove(absOutput); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("%w: remove stale output: %w", ErrPDFFailed, err)
	}
	if err := runPDFChrome(ctx, chromePath, args, absOutput, resolvePDFTimeout(meta.PDFTimeout, os.Getenv)); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "  Note: PDF styling may differ slightly from the browser view.\n")
	fmt.Fprintf(os.Stderr, "  For the best visual experience, use --format html or --format report.\n")

	return nil
}

// resolvePDFTimeout picks the render bound: an explicit meta value, else a
// valid positive VIGOLIUM_PDF_TIMEOUT duration, else DefaultPDFTimeout.
func resolvePDFTimeout(explicit time.Duration, getenv func(string) string) time.Duration {
	if explicit > 0 {
		return explicit
	}
	if v := strings.TrimSpace(getenv("VIGOLIUM_PDF_TIMEOUT")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return DefaultPDFTimeout
}

// pdfWrittenMarker is what headless Chrome prints to stderr once the PDF is
// on disk ("6686 bytes written to file /out/report.pdf").
const pdfWrittenMarker = "bytes written to file"

// pdfTeardownGrace is how long Chrome may take to exit after it reported the
// PDF written. Some hosts wedge Chrome's shutdown (a teardown watchdog, a
// helper that cannot reach its parent); the document is already complete, so
// the export should not wait out the whole timeout or fail on the exit code.
var pdfTeardownGrace = 5 * time.Second

// runPDFChrome runs Chrome until it exits, bounded by timeout and ctx. Chrome
// is started in its own process group so a timeout kills its renderer/GPU
// children too, not just the browser process. Once Chrome reports the PDF
// written and outputPath holds a non-empty file, the export counts as done:
// a slow or failing teardown is cut short after pdfTeardownGrace.
func runPDFChrome(ctx context.Context, chromePath string, args []string, outputPath string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// teardown is cancelled separately so a grace kill is not mistaken for
	// the caller's timeout.
	runCtx, teardown := context.WithCancel(ctx)
	defer teardown()

	written := make(chan struct{})
	stderr := &tailBuffer{max: pdfStderrTailBytes, marker: []byte(pdfWrittenMarker), seen: written}
	cmd := exec.CommandContext(runCtx, chromePath, args...)
	cmd.Stdout = nil
	cmd.Stderr = stderr
	setPDFProcessGroup(cmd)
	// Children that inherited the stderr pipe can keep it open after the
	// group kill; don't wait on them forever.
	cmd.WaitDelay = 5 * time.Second

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%w: start chrome: %w", ErrPDFFailed, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var err error
	select {
	case err = <-done:
	case <-written:
		select {
		case err = <-done:
		case <-time.After(pdfTeardownGrace):
			teardown()
			err = <-done
		}
	}
	if stderr.sawMarker() && pdfOutputWritten(outputPath) {
		return nil
	}
	if err == nil {
		if pdfOutputWritten(outputPath) {
			return nil
		}
		err = errors.New("chrome exited without writing the PDF")
	}

	tail := strings.TrimSpace(stderr.String())
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		err = fmt.Errorf("%w: Chrome did not finish within %s (raise it with VIGOLIUM_PDF_TIMEOUT)", ErrPDFFailed, timeout)
	case ctx.Err() != nil:
		err = fmt.Errorf("%w: %w", ErrPDFFailed, ctx.Err())
	default:
		err = fmt.Errorf("%w: chrome: %w", ErrPDFFailed, err)
	}
	if tail != "" {
		err = fmt.Errorf("%w\nchrome stderr (last %d bytes):\n%s", err, len(tail), tail)
	}
	return err
}

// pdfOutputWritten reports whether path holds a non-empty file.
func pdfOutputWritten(path string) bool {
	if path == "" {
		return false
	}
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Size() > 0
}

// pdfChromeParams is everything the Chrome argument list depends on.
type pdfChromeParams struct {
	UserDataDir string
	OutputPath  string
	HTMLPath    string
	NoSandbox   bool
}

// pdfChromeArgs assembles the headless print-to-pdf command line. Pure, so
// the sandbox and profile flags are table-testable without launching Chrome.
func pdfChromeArgs(p pdfChromeParams) []string {
	args := []string{
		"--headless",
		"--disable-gpu",
		"--disable-software-rasterizer",
		"--run-all-compositor-stages-before-draw",
		"--no-pdf-header-footer",
		"--no-first-run",
		"--no-default-browser-check",
		"--virtual-time-budget=5000",
	}
	if p.UserDataDir != "" {
		args = append(args, "--user-data-dir="+p.UserDataDir)
	}
	if p.NoSandbox {
		args = append(args, "--no-sandbox")
	}
	return append(args, "--print-to-pdf="+p.OutputPath, "file://"+filepath.ToSlash(p.HTMLPath))
}

// pdfHost is the slice of the host the sandbox decision reads, injected so
// every branch is testable on any OS.
type pdfHost struct {
	goos   string
	euid   int
	exists func(string) bool
	getenv func(string) string
}

func currentPDFHost() pdfHost {
	return pdfHost{
		goos: runtime.GOOS,
		euid: os.Geteuid(),
		exists: func(p string) bool {
			_, err := os.Stat(p)
			return err == nil
		},
		getenv: os.Getenv,
	}
}

// pdfNoSandbox decides whether Chrome must run with --no-sandbox, and why.
// The sandbox stays on unless the operator opts out (VIGOLIUM_CHROME_NO_SANDBOX=1)
// or the host cannot provide it: Chrome refuses to start sandboxed as root on
// Linux, and containers usually lack the namespaces it needs. The container
// test mirrors rod's (and spitolas') so every browser launch agrees.
func pdfNoSandbox(h pdfHost) (bool, string) {
	if utils.Truthy(h.getenv("VIGOLIUM_CHROME_NO_SANDBOX")) {
		return true, "VIGOLIUM_CHROME_NO_SANDBOX=1"
	}
	if h.goos != "linux" {
		return false, ""
	}
	if h.euid == 0 {
		return true, "running as root"
	}
	if h.exists("/.dockerenv") || h.exists("/.containerenv") || h.exists("/run/.containerenv") ||
		h.getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true, "running in a container"
	}
	return false, ""
}

// tailBuffer is an io.Writer that keeps only the last max bytes written. When
// marker is set, seen is closed the first time the marker appears.
type tailBuffer struct {
	mu     sync.Mutex
	max    int
	buf    []byte
	marker []byte
	seen   chan struct{}
	found  bool
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := len(p)
	if len(p) >= t.max {
		t.buf = append(t.buf[:0], p[len(p)-t.max:]...)
	} else {
		if over := len(t.buf) + len(p) - t.max; over > 0 {
			t.buf = append(t.buf[:0], t.buf[over:]...)
		}
		t.buf = append(t.buf, p...)
	}
	// The buffer is contiguous, so a marker split across writes is still found.
	if !t.found && len(t.marker) > 0 && bytes.Contains(t.buf, t.marker) {
		t.found = true
		if t.seen != nil {
			close(t.seen)
		}
	}
	return n, nil
}

func (t *tailBuffer) sawMarker() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.found
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	// The tail may start mid-rune; drop leading continuation bytes.
	b := t.buf
	for len(b) > 0 && b[0]&0xC0 == 0x80 {
		b = b[1:]
	}
	return string(b)
}
