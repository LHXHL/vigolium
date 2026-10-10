package helperblob

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func packed(t *testing.T, raw []byte) ([]byte, Pin) {
	t.Helper()
	var buf bytes.Buffer
	if err := Compress(&buf, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return buf.Bytes(), Pin{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(raw))}
}

func TestInstallRoundTripAndMismatch(t *testing.T) {
	raw := bytes.Repeat([]byte("helper-bytes-"), 10000)
	blob, pin := packed(t, raw)
	dir := t.TempDir()

	path, err := Install(bytes.NewReader(blob), pin, dir, "helper")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, raw) {
		t.Fatal("round trip changed the bytes")
	}
	if !Cached(path, pin) {
		t.Error("Cached() false right after Install")
	}

	bad := pin
	bad.SHA256 = strings.Repeat("0", 64)
	_, err = Install(bytes.NewReader(blob), bad, t.TempDir(), "helper")
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("err = %v, want ErrChecksumMismatch", err)
	}
	if !strings.Contains(err.Error(), "expected sha256 "+bad.SHA256) || !strings.Contains(err.Error(), "got "+pin.SHA256) {
		t.Errorf("error %q must name expected and actual sha256", err)
	}
}

// A stream that decompresses past the pinned size is cut off and rejected,
// bounding a decompression bomb to the pinned size.
func TestDecompressRefusesOversizedOutput(t *testing.T) {
	blob, pin := packed(t, make([]byte, 4096))
	if _, _, err := Decompress(io.Discard, bytes.NewReader(blob), pin.Size-1); err == nil {
		t.Fatal("Decompress accepted output larger than the limit")
	}
	small := pin
	small.Size = 100
	dir := t.TempDir()
	_, err := Install(bytes.NewReader(blob), small, dir, "helper")
	if err == nil {
		t.Fatal("Install accepted a stream larger than the pin")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("files left behind after a refused install: %v", entries)
	}
}

func TestParsePinValidates(t *testing.T) {
	for _, in := range []string{
		`{}`,
		`{"sha256":"abc","size":10}`,
		`{"sha256":"` + strings.Repeat("a", 64) + `","size":0}`,
		`not json`,
	} {
		if _, err := ParsePin([]byte(in)); err == nil {
			t.Errorf("ParsePin(%q) accepted an invalid pin", in)
		}
	}
	p, err := ParsePin([]byte(`{"sha256":"` + strings.Repeat("a", 64) + `","size":5,"platform":"linux/amd64"}`))
	if err != nil || p.Short() != strings.Repeat("a", 12) || p.Platform != "linux/amd64" {
		t.Fatalf("ParsePin = %+v, %v", p, err)
	}
}
