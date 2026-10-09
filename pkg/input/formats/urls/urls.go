package urls

import (
	"bufio"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
	"go.uber.org/zap"
)

// URLListFormat parses a plain URL list: one URL per line, blank lines and
// `#` comment lines ignored (the same rule as `-T` target lists).
type URLListFormat struct {
	opts formats.InputFormatOptions
}

// IsTargetLine reports whether a whitespace-trimmed line of a URL / target list
// holds a target: blank lines and `#` comments do not. Shared by this parser
// and the CLI's -T target-list reader so both skip the same lines.
func IsTargetLine(line string) bool {
	return line != "" && !strings.HasPrefix(line, "#")
}

// New creates a URL list parser.
func New() *URLListFormat {
	return &URLListFormat{}
}

var _ formats.Format = &URLListFormat{}

// Name returns the name of the format
func (j *URLListFormat) Name() string {
	return "urls"
}

func (j *URLListFormat) SetOptions(options formats.InputFormatOptions) {
	j.opts = options
}

// Parse parses the input and calls the provided callback
// function for each RawRequest it discovers.
func (j *URLListFormat) Parse(input string, resultsCb formats.ParseReqRespCallback) error {
	file, err := os.Open(input)
	if err != nil {
		return errors.Wrap(err, "could not open URL list")
	}
	defer func() { _ = file.Close() }()
	sc := bufio.NewScanner(file)
	// Grow the token buffer beyond bufio's 64 KiB default so a long URL line
	// (data: URLs, big query strings) doesn't silently truncate the scan.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !IsTargetLine(line) {
			continue
		}
		rawRequest, err := httpmsg.GetRawRequestFromURL(line)
		if err != nil {
			zap.L().Warn("urls: Could not get raw request from URL", zap.String("url", line), zap.Error(err))
			continue
		}
		// Honor the callback's cancellation signal, matching the other input formats.
		if !resultsCb(rawRequest) {
			return nil
		}
	}
	// Surface a scan error (e.g. a line over the buffer cap) instead of silently
	// reporting success on a partially-read file.
	if err := sc.Err(); err != nil {
		return errors.Wrap(err, "failed to read url list")
	}

	return nil
}

// Count returns the number of target lines (non-blank, non-comment) in the
// file, the same lines Parse visits.
func (j *URLListFormat) Count(input string) (int64, error) {
	file, err := os.Open(input)
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()

	var count int64
	sc := bufio.NewScanner(file)
	// Match Parse's larger token buffer so Count and Parse agree on long lines.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if IsTargetLine(strings.TrimSpace(sc.Text())) {
			count++
		}
	}
	return count, sc.Err()
}
