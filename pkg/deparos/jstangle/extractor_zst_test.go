package jstangle

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/internal/helperblob"
)

// setEmbeddedForTest swaps the embedded helper for a synthetic one and
// restores the real one when the test ends. Not parallel-safe: the embedded
// blob is package state.
func setEmbeddedForTest(t *testing.T, blob, pin []byte) {
	t.Helper()
	oldBlob, oldPin, oldName := embeddedBlob, embeddedPinData, binaryName
	embeddedBlob, embeddedPinData = blob, pin
	if binaryName == "" {
		binaryName = "jstangle"
	}
	embeddedPinOnce = sync.Once{}
	t.Cleanup(func() {
		embeddedBlob, embeddedPinData, binaryName = oldBlob, oldPin, oldName
		embeddedPinOnce = sync.Once{}
	})
}

// fakeHelper returns a compressed payload and the pin of its raw bytes.
func fakeHelper(t *testing.T) (raw, blob []byte, pin helperblob.Pin) {
	t.Helper()
	raw = make([]byte, 64<<10)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := helperblob.Compress(&buf, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return raw, buf.Bytes(), helperblob.Pin{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(raw))}
}

func marshalPin(t *testing.T, pin helperblob.Pin) []byte {
	t.Helper()
	b, err := pin.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The embedded helper is zstd-compressed; extraction must reproduce the exact
// uncompressed bytes and record the pinned (uncompressed) sha256 as checksum.
func TestExtractor_CompressedRoundTrip(t *testing.T) {
	raw, blob, pin := fakeHelper(t)
	setEmbeddedForTest(t, blob, marshalPin(t, pin))

	ext, err := NewExtractor(&Config{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewExtractor: %v", err)
	}
	cached, err := ext.GetBinary()
	if err != nil {
		t.Fatalf("GetBinary: %v", err)
	}
	got, err := os.ReadFile(cached.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("extracted %d bytes differ from the uncompressed helper (%d bytes)", len(got), len(raw))
	}
	if cached.Checksum != pin.SHA256 {
		t.Errorf("checksum = %s, want the pinned uncompressed sha256 %s", cached.Checksum, pin.SHA256)
	}
	if info, err := os.Stat(cached.Path); err != nil || info.Mode().Perm()&0o111 == 0 {
		t.Errorf("extracted helper is not executable (err=%v)", err)
	}
	entries, _ := os.ReadDir(ext.CacheDir())
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file %s left behind", e.Name())
		}
	}
}

// A blob that does not decompress to its pin is a hard error naming both
// hashes, and nothing is left at the binary path.
func TestExtractor_PinMismatchIsHardError(t *testing.T) {
	_, blob, pin := fakeHelper(t)
	wrong := pin
	wrong.SHA256 = strings.Repeat("ab", 32)
	setEmbeddedForTest(t, blob, marshalPin(t, wrong))

	dir := t.TempDir()
	ext, err := NewExtractor(&Config{CacheDir: dir})
	if err != nil {
		t.Fatalf("NewExtractor: %v", err)
	}
	_, err = ext.GetBinary()
	if err == nil {
		t.Fatal("GetBinary succeeded with a mismatching pin")
	}
	if !errors.Is(err, helperblob.ErrChecksumMismatch) || !errors.Is(err, ErrExtractionFailed) {
		t.Errorf("error %v should wrap ErrChecksumMismatch and ErrExtractionFailed", err)
	}
	for _, want := range []string{wrong.SHA256, pin.SHA256} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name sha256 %s", err, want)
		}
	}
	if _, statErr := os.Stat(filepath.Join(dir, binaryName)); !os.IsNotExist(statErr) {
		t.Errorf("a binary was installed despite the mismatch (stat err=%v)", statErr)
	}
}

func TestExtractor_RefusesForeignPlatformPin(t *testing.T) {
	_, blob, pin := fakeHelper(t)
	pin.Platform = "plan9/mips"
	setEmbeddedForTest(t, blob, marshalPin(t, pin))
	ext, err := NewExtractor(&Config{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewExtractor: %v", err)
	}
	if _, err := ext.GetBinary(); err == nil || !strings.Contains(err.Error(), "plan9/mips") {
		t.Fatalf("err = %v, want a platform refusal naming plan9/mips", err)
	}
}
