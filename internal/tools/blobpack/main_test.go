package main

import (
	"bytes"
	"encoding/binary"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/helperblob"
)

// fakeELF returns a >1 MiB linux/amd64 "executable" carrying marker.
func fakeELF(marker string) []byte {
	raw := bytes.Repeat([]byte{0x90}, 1<<20+512)
	copy(raw, []byte{0x7f, 'E', 'L', 'F', 2, 1})
	binary.LittleEndian.PutUint16(raw[18:], 0x3E)
	copy(raw[4096:], marker)
	return raw
}

func TestPackWritesPinAndIsContentAddressed(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "jstangle-linux-amd64")
	raw := fakeELF("fingerprint-123")
	if err := os.WriteFile(in, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := pack(in, in, "linux/amd64", "fingerprint-123"); err != nil {
		t.Fatalf("pack: %v", err)
	}
	pinData, err := os.ReadFile(in + ".pin")
	if err != nil {
		t.Fatal(err)
	}
	pin, err := helperblob.ParsePin(pinData)
	if err != nil {
		t.Fatal(err)
	}
	if pin.Platform != "linux/amd64" || pin.SourceHash != "fingerprint-123" || pin.Size != int64(len(raw)) {
		t.Errorf("pin = %+v", pin)
	}
	blob, _ := os.ReadFile(in + ".zst")
	if _, err := helperblob.Install(bytes.NewReader(blob), pin, dir, "out"); err != nil {
		t.Fatalf("packed blob does not install: %v", err)
	}

	// Unchanged input: the .zst is not rewritten.
	before, _ := os.Stat(in + ".zst")
	msg, err := pack(in, in, "linux/amd64", "fingerprint-123")
	if err != nil || !strings.Contains(msg, "is current") {
		t.Fatalf("repack = %q, %v; want a no-op", msg, err)
	}
	after, _ := os.Stat(in + ".zst")
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("an unchanged blob was recompressed")
	}

	// A marker the blob does not carry is not recorded.
	if _, err := pack(in, in, "linux/amd64", "other-fingerprint"); err != nil {
		t.Fatal(err)
	}
	pinData, _ = os.ReadFile(in + ".pin")
	if strings.Contains(string(pinData), "other-fingerprint") {
		t.Error("pin records a fingerprint the blob does not contain")
	}
}

func TestPackRefusesWrongPlatform(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "blob")
	if err := os.WriteFile(in, fakeELF(""), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := pack(in, in, "darwin/arm64", ""); err == nil || !strings.Contains(err.Error(), "linux/amd64") {
		t.Fatalf("err = %v, want a wrong-platform refusal naming linux/amd64", err)
	}
	if _, err := os.Stat(in + ".zst"); !os.IsNotExist(err) {
		t.Error("a wrong-platform blob was packed")
	}
}

func TestRenderPinsIsValidGo(t *testing.T) {
	src, err := renderPins("bin", map[string]helperblob.Pin{
		"linux_amd64": {SHA256: strings.Repeat("a", 64), Size: 10, Platform: "linux/amd64"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "//go:build audit_external") {
		t.Error("generated pins file is not gated on audit_external")
	}
	if _, err := parser.ParseFile(token.NewFileSet(), "pins_gen.go", src, 0); err != nil {
		t.Fatalf("generated pins file does not parse: %v", err)
	}
}
