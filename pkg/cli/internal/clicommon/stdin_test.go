package clicommon

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// blockingReader never returns and never closes, which is what a shell pipe
// whose producer is still running looks like. Before the deadline existed this
// is what hung the process: io.ReadAll on one of these never comes back.
type blockingReader struct{ release chan struct{} }

func (b *blockingReader) Read(p []byte) (int, error) {
	<-b.release
	return 0, io.EOF
}

func TestReadBoundedTimesOutOnAProducerThatNeverFinishes(t *testing.T) {
	r := &blockingReader{release: make(chan struct{})}
	defer close(r.release)

	start := time.Now()
	_, err := ReadBounded(r, "stdin", 1024, 100*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a producer that never finishes must not read successfully")
	}
	if !errors.Is(err, ErrStdinTimeout) {
		t.Errorf("error = %v, want one wrapping ErrStdinTimeout", err)
	}
	// The message has to name the dial that changes the outcome; "vigolium hung"
	// is otherwise indistinguishable from "the producer is slow".
	if !strings.Contains(err.Error(), "--input-read-timeout") {
		t.Errorf("timeout must name the flag that adjusts it, got: %v", err)
	}
	if elapsed > time.Second {
		t.Errorf("returned after %s; the deadline was 100ms", elapsed)
	}
}

func TestReadBoundedReturnsCompleteInput(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"no final line":  "one\ntwo",
		"crlf":           "one\r\ntwo\r\n",
		"unicode":        "héllo — wörld\n",
		"trailing bytes": strings.Repeat("x", 4096),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ReadBounded(strings.NewReader(in), "stdin", 0, time.Second)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(got) != in {
				t.Errorf("input was altered:\ngot  %q\nwant %q", got, in)
			}
		})
	}
}

func TestReadBoundedRejectsOversizeInputInsteadOfTruncating(t *testing.T) {
	// Silently truncating turns an oversize input into a confusing parse error
	// somewhere downstream; the limit has to be reported as a limit.
	_, err := ReadBounded(bytes.NewReader(bytes.Repeat([]byte("a"), 100)), "stdin", 10, time.Second)
	if err == nil {
		t.Fatal("input past the limit must be rejected")
	}
	if !errors.Is(err, ErrStdinTooLarge) {
		t.Errorf("error = %v, want one wrapping ErrStdinTooLarge", err)
	}
}

func TestReadBoundedWithZeroTimeoutHasNoDeadline(t *testing.T) {
	// A zero timeout is the documented "no deadline" value, so a slow but
	// finite producer must still be read in full.
	slow := io.MultiReader(strings.NewReader("part-one "), &delayedReader{
		data:  []byte("part-two"),
		delay: 150 * time.Millisecond,
	})
	got, err := ReadBounded(slow, "stdin", 0, 0)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "part-one part-two" {
		t.Errorf("got %q", got)
	}
}

type delayedReader struct {
	data  []byte
	delay time.Duration
	done  bool
}

func (d *delayedReader) Read(p []byte) (int, error) {
	if d.done {
		return 0, io.EOF
	}
	time.Sleep(d.delay)
	n := copy(p, d.data)
	d.done = true
	return n, nil
}

func TestReadBoundedPropagatesReadErrors(t *testing.T) {
	want := errors.New("device gone")
	_, err := ReadBounded(&failingReader{err: want}, "stdin", 0, time.Second)
	if !errors.Is(err, want) {
		t.Errorf("error = %v, want it to wrap %v", err, want)
	}
}

type failingReader struct{ err error }

func (f *failingReader) Read(p []byte) (int, error) { return 0, f.err }
