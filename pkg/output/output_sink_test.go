package output

import (
	"bytes"
	"strings"
	"testing"
)

// countingWriteCloser records how many bytes the writer actually handed it.
type countingWriteCloser struct {
	buf bytes.Buffer
}

func (c *countingWriteCloser) Write(p []byte) (int, error) { return c.buf.Write(p) }
func (c *countingWriteCloser) Close() error                { return nil }

func sinkTestEvent() *ResultEvent {
	return &ResultEvent{
		ModuleID: "test-module",
		Host:     "example.test",
		URL:      "http://example.test/",
		Request:  "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
		Response: "HTTP/1.1 200 OK\r\n\r\n" + strings.Repeat("x", 4096),
	}
}

// TestWriteSkipsJSONWithNoSink covers the deferred-export shape: JSONOutput is
// set (jsonl asked for it) but live stdout is suppressed and no live file was
// opened, so the event has no sink at all and marshaling it is pure waste. The
// callback must still fire — it is how --events counts findings.
func TestWriteSkipsJSONWithNoSink(t *testing.T) {
	var seen int
	w := &StandardWriter{
		JSONOutput:    true,
		DisableStdout: true,
		OnEvent:       func(*ResultEvent) { seen++ },
	}
	if err := w.Write(sinkTestEvent()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if seen != 1 {
		t.Errorf("OnEvent fired %d times, want 1", seen)
	}
}

// TestWriteStillSerializesForEachSink pins the other side: every configuration
// that does have a consumer must still produce bytes.
func TestWriteStillSerializesForEachSink(t *testing.T) {
	t.Run("live file with stdout disabled", func(t *testing.T) {
		f := &countingWriteCloser{}
		w := &StandardWriter{JSONOutput: true, DisableStdout: true, outputFile: f}
		if err := w.Write(sinkTestEvent()); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if f.buf.Len() == 0 {
			t.Error("nothing written to the live output file")
		}
	})

	t.Run("live file with console stdout", func(t *testing.T) {
		f := &countingWriteCloser{}
		w := &StandardWriter{JSONOutput: false, DisableStdout: true, outputFile: f}
		if err := w.Write(sinkTestEvent()); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if f.buf.Len() == 0 {
			t.Error("nothing written to the live output file")
		}
	})
}

// TestWriteFileOnlyNoFile asserts WriteFileOnly stops before the encode when
// there is no file to write to, and still writes when there is.
func TestWriteFileOnlyNoFile(t *testing.T) {
	w := &StandardWriter{JSONOutput: true}
	if err := w.WriteFileOnly(sinkTestEvent()); err != nil {
		t.Fatalf("WriteFileOnly with no file: %v", err)
	}

	f := &countingWriteCloser{}
	w = &StandardWriter{JSONOutput: true, outputFile: f}
	if err := w.WriteFileOnly(sinkTestEvent()); err != nil {
		t.Fatalf("WriteFileOnly: %v", err)
	}
	if f.buf.Len() == 0 {
		t.Error("nothing written to the output file")
	}
}
