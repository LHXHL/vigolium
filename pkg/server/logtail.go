package server

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/gofiber/fiber/v3"
)

const (
	// defaultLogTailBytes is how much of a runtime.log the log endpoints return
	// when the caller doesn't say. A scan or agent run that has been going for
	// hours writes a log measured in hundreds of megabytes, and the endpoints
	// used to os.ReadFile the whole thing — per request, with the Workbench
	// polling every five seconds while the scan runs, so one watched scan turned
	// into a sustained multi-hundred-megabyte allocation loop. Nothing consuming
	// these endpoints wants the head of such a file: a log viewer shows the end.
	defaultLogTailBytes = 2 << 20 // 2 MiB

	// maxLogTailBytes bounds what ?max_bytes= can ask for, so the cap can be
	// raised for a deliberate download without becoming unbounded again.
	maxLogTailBytes = 64 << 20 // 64 MiB
)

// queryByteLimit resolves a ?max_bytes= query parameter against a default and a
// hard cap. Absent, unparseable, or non-positive values yield def. Shared by the
// log endpoints and HandleAgentSessionArtifact so one public parameter has one
// parser rather than one per endpoint.
func queryByteLimit(c fiber.Ctx, def, hardCap int64) int64 {
	v := c.Query("max_bytes")
	if v == "" {
		return def
	}
	parsed, err := strconv.ParseInt(v, 10, 64)
	if err != nil || parsed <= 0 {
		return def
	}
	return min(parsed, hardCap)
}

// readLogTail returns up to limit bytes from the end of the file at path, along
// with the file's total size.
//
// Reading the tail rather than the head is the whole point — the newest lines
// are the ones anyone asked for — and seeking to size-limit means the bytes
// skipped are never allocated. The buffer is sized exactly, since both branches
// already know the byte count; io.ReadAll would start at 512 bytes and grow by
// append, which on a 2 MiB tail is ~2x the allocation and 6x the allocations.
//
// When the file is longer than the limit the returned slice starts mid-line;
// callers surface that via response headers rather than trying to repair it,
// since the first partial line is cheap for a reader to discard and expensive
// for us to find.
func readLogTail(path string, limit int64) (data []byte, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	size = info.Size()

	n := size
	if size > limit {
		if _, err = f.Seek(size-limit, io.SeekStart); err != nil {
			return nil, size, err
		}
		n = limit
	}

	buf := make([]byte, n)
	// ReadFull over ReadAll: a log is appended to concurrently, so a short read
	// at EOF is expected rather than an error.
	read, err := io.ReadFull(f, buf)
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		err = nil
	}
	return buf[:read], size, err
}

// sendLogTail writes the tail of a log file as text/plain, optionally stripping
// ANSI escapes. Truncation is reported in headers rather than in the body so
// the payload stays exactly the log's own bytes: X-Log-Size is the file's full
// length, X-Log-Truncated says whether the response is only its end.
func sendLogTail(c fiber.Ctx, path string, strip bool) error {
	data, size, err := readLogTail(path, queryByteLimit(c, defaultLogTailBytes, maxLogTailBytes))
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to read runtime.log: %w", err))
	}
	// Strip after the tail is taken, not before: stripping the whole file would
	// reintroduce the allocation the tail read just avoided. An escape sequence
	// straddling the cut is the one casualty, and it is a few stray bytes on the
	// first line.
	if strip {
		data = stripANSIBytes(data)
	}
	c.Set("X-Log-Size", strconv.FormatInt(size, 10))
	c.Set("X-Log-Truncated", strconv.FormatBool(int64(len(data)) < size))
	c.Set("Content-Type", "text/plain; charset=utf-8")
	return c.Send(data)
}
