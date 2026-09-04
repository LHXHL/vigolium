package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// logStaleAfter is how long a "running" scan may go without writing before its
// row is treated as abandoned rather than live.
//
// Two minutes: a scan writes phase lines, the [status] ticker and finding lines
// continuously, so a live run is never silent this long, while a run killed by a
// deadline or SIGKILL is silent forever. Erring long is the safe direction — the
// cost of guessing "still running" on a live scan is nothing (it tails, which is
// what the operator wanted), and the cost of guessing it on a dead one is the
// unbounded stall this exists to prevent.
const logStaleAfter = 2 * time.Minute

// logSourceIsStale reports whether a session whose row still says "running" has
// in fact stopped writing. Consulted only to decide auto-follow; an explicit
// --follow always wins, because an operator who typed it may be waiting for a
// scan that is genuinely just slow to start.
func logSourceIsStale(src *logSource) bool {
	if src == nil {
		return false
	}
	// The log file's mtime is the most direct liveness signal available: it is
	// touched by the writing process itself, so it cannot outlive it the way a
	// status column can.
	if src.filePath != "" {
		if info, err := os.Stat(src.filePath); err == nil {
			return time.Since(info.ModTime()) > logStaleAfter
		}
	}
	// No file (persist_logs off, DB fallback): fall back to the row's own
	// updated_at, which the scan logger's batcher advances as it writes.
	if !src.updatedAt.IsZero() {
		return time.Since(src.updatedAt) > logStaleAfter
	}
	return false
}

// noticeMarkers are the bracketed tags the scan uses for operator notices,
// referenced from the producer rather than re-typed here — recoloring or
// renaming a tag would otherwise silently stop this finding anything, with no
// compile error and no failing test.
var noticeMarkers = []string{runner.NoticeMarkerBlock, runner.NoticeMarkerPacing}

// printElidedNotices prints any WAF notice that fell above the --tail window.
//
// The reader defaults to the last 200 lines, but a WAF notice fires EARLY — the
// edge is fingerprinted on the first clean response — so the tail is
// structurally the wrong end of the log for the most important thing in it, and
// seeing one required knowing to pass --full. Scanning only the elided head
// keeps the cost proportional to what is being hidden, and the lines are
// reprinted under a header so it is clear they are not part of the tail.
func printElidedNotices(path string, startOffset int64) {
	if startOffset <= 0 {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	var found []string
	reader := bufio.NewReader(io.LimitReader(f, startOffset))
	for {
		line, err := reader.ReadString('\n')
		if containsNoticeMarker(line) {
			found = append(found, strings.TrimRight(line, "\r\n"))
		}
		if err != nil {
			break
		}
		// A log full of notices is a pathological case; cap so this can never
		// print more than the tail it precedes.
		if len(found) >= 20 {
			break
		}
	}
	if len(found) == 0 {
		return
	}
	_, _ = fmt.Fprintf(os.Stdout, "%s %s\n",
		terminal.WarnPrefix(),
		terminal.Gray(fmt.Sprintf("%d earlier notice(s) above the --tail window (pass --full for the whole log):", len(found))))
	for _, line := range found {
		_, _ = fmt.Fprintln(os.Stdout, line)
	}
	_, _ = fmt.Fprintln(os.Stdout)
}

func containsNoticeMarker(line string) bool {
	if line == "" {
		return false
	}
	for _, marker := range noticeMarkers {
		if strings.Contains(line, marker) {
			return true
		}
	}
	return false
}
