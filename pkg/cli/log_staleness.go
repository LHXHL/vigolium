package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/terminal"
)

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
