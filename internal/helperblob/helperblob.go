// Package helperblob packs and unpacks the Bun-compiled helper executables
// vigolium carries (jstangle, vigolium-audit).
//
// The helpers are zstd-compressed at stage time (internal/tools/blobpack) and
// embedded as <name>.zst next to a small JSON pin file (<name>.pin). The pin
// records the sha256 and size of the UNCOMPRESSED executable, so the pinned
// hash is the same value it was before compression: cache directories keyed by
// it do not move, and a decompressed blob that does not hash to the pin is a
// hard error rather than an executable written to disk.
//
// The pin also carries the build platform and, for jstangle, the TypeScript
// source fingerprint. Both are plain strings embedded uncompressed in the Go
// binary, which keeps the release gates in build/npm/build.mjs able to read
// them with a byte search even though the executable bytes are compressed.
package helperblob

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
)

// ErrChecksumMismatch is returned when a decompressed or downloaded helper does
// not hash to its pinned sha256. It is never retried or ignored: the bytes are
// discarded and the caller surfaces the error.
var ErrChecksumMismatch = errors.New("helper checksum mismatch")

// Pin describes one uncompressed helper executable.
type Pin struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	// Platform is "<goos>/<goarch>" decoded from the executable header at pack
	// time; empty when the format was not recognised.
	Platform string `json:"platform,omitempty"`
	// SourceHash is the jstangle source fingerprint, recorded only when the
	// packer was given one AND the executable contains it verbatim.
	SourceHash string `json:"source_hash,omitempty"`
}

// ParsePin decodes a pin file and validates its fields.
func ParsePin(data []byte) (Pin, error) {
	var p Pin
	if err := json.Unmarshal(data, &p); err != nil {
		return Pin{}, fmt.Errorf("parse helper pin: %w", err)
	}
	if err := p.Validate(); err != nil {
		return Pin{}, err
	}
	return p, nil
}

// Validate checks that the pin names a plausible executable.
func (p Pin) Validate() error {
	if b, err := hex.DecodeString(p.SHA256); err != nil || len(b) != sha256.Size {
		return fmt.Errorf("helper pin: sha256 %q is not a 64-char hex digest", p.SHA256)
	}
	if p.Size <= 0 {
		return fmt.Errorf("helper pin: size %d must be positive", p.Size)
	}
	return nil
}

// Short returns the first 12 hex characters of the pinned sha256, the cache
// directory key both extractors use.
func (p Pin) Short() string {
	if len(p.SHA256) < 12 {
		return p.SHA256
	}
	return p.SHA256[:12]
}

// Marshal renders the pin file written next to a packed blob.
func (p Pin) Marshal() ([]byte, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Compress writes src to dst as a single zstd frame at the best compression
// level, with the frame checksum on. Used only at stage time.
func Compress(dst io.Writer, src io.Reader) error {
	enc, err := zstd.NewWriter(dst,
		zstd.WithEncoderLevel(zstd.SpeedBestCompression),
		zstd.WithEncoderCRC(true),
	)
	if err != nil {
		return err
	}
	if _, err := io.Copy(enc, src); err != nil {
		_ = enc.Close()
		return err
	}
	return enc.Close()
}

// Decompress streams the zstd data in src to dst, refusing to write more than
// limit bytes. It returns the sha256 and length of what was written.
func Decompress(dst io.Writer, src io.Reader, limit int64) (sum string, n int64, err error) {
	dec, err := zstd.NewReader(src, zstd.WithDecoderConcurrency(1))
	if err != nil {
		return "", 0, fmt.Errorf("open zstd stream: %w", err)
	}
	defer dec.Close()
	h := sha256.New()
	// Read one byte past the limit so an oversized stream is detected rather
	// than silently truncated into something that might still hash-match.
	n, err = io.Copy(io.MultiWriter(dst, h), io.LimitReader(dec, limit+1))
	if err != nil {
		return "", n, fmt.Errorf("decompress helper: %w", err)
	}
	if n > limit {
		return "", n, fmt.Errorf("decompress helper: output exceeds the pinned size of %d bytes", limit)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// Cached reports whether dir/name already holds a regular file of the pinned
// size. Cache directories are keyed by the pinned hash, so a file of the right
// size there was written by Install after its hash was verified.
func Cached(path string, pin Pin) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Size() == pin.Size
}

// Install decompresses the zstd stream src into dir/name, verifying the result
// against pin before it becomes visible at its final path. The file is written
// under a per-process temp name and renamed into place, so concurrent
// extractors never observe a partial executable. A hash or size mismatch
// returns an error wrapping ErrChecksumMismatch that names the expected and
// actual values.
func Install(src io.Reader, pin Pin, dir, name string) (string, error) {
	if err := pin.Validate(); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create helper cache dir: %w", err)
	}
	dst := filepath.Join(dir, name)

	tmpFile, err := os.CreateTemp(dir, name+".*.tmp")
	if err != nil {
		return "", fmt.Errorf("create helper temp file: %w", err)
	}
	tmp := tmpFile.Name()
	fail := func(err error) (string, error) {
		_ = tmpFile.Close()
		_ = os.Remove(tmp)
		return "", err
	}

	sum, n, err := Decompress(tmpFile, src, pin.Size)
	if err != nil {
		return fail(err)
	}
	if n != pin.Size || sum != pin.SHA256 {
		return fail(fmt.Errorf("%w for %s: expected sha256 %s (%d bytes), got %s (%d bytes)",
			ErrChecksumMismatch, name, pin.SHA256, pin.Size, sum, n))
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("write helper binary: %w", err)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("chmod helper binary: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		// Windows refuses to replace a file another process is executing. The
		// directory is keyed by content hash, so a complete file already at
		// dst is byte-identical to what we just verified: adopt it.
		if Cached(dst, pin) {
			return dst, nil
		}
		return "", fmt.Errorf("install helper binary: %w", err)
	}
	return dst, nil
}

// DetectPlatform inspects the leading bytes of an executable and reports the
// GOOS/GOARCH it targets. ok is false when the container format is not
// recognised; goarch is "" when the format is known but the machine field is
// not. It reads only the container magic (ELF / Mach-O / PE) and machine field.
func DetectPlatform(data []byte) (goos, goarch string, ok bool) {
	// ELF: e_ident[EI_DATA] at offset 5 gives endianness; e_machine is a
	// 2-byte field at offset 0x12.
	if len(data) >= 20 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		var machine uint16
		if data[5] == 2 { // ELFDATA2MSB
			machine = binary.BigEndian.Uint16(data[18:20])
		} else {
			machine = binary.LittleEndian.Uint16(data[18:20])
		}
		switch machine {
		case 0x3E: // EM_X86_64
			goarch = "amd64"
		case 0xB7: // EM_AARCH64
			goarch = "arm64"
		}
		return "linux", goarch, true
	}

	// Mach-O 64-bit thin, little-endian. MH_MAGIC_64 (0xFEEDFACF) is
	// byte-reversed on disk.
	if len(data) >= 8 && data[0] == 0xcf && data[1] == 0xfa && data[2] == 0xed && data[3] == 0xfe {
		switch binary.LittleEndian.Uint32(data[4:8]) {
		case 0x01000007: // CPU_TYPE_X86_64
			goarch = "amd64"
		case 0x0100000c: // CPU_TYPE_ARM64
			goarch = "arm64"
		}
		return "darwin", goarch, true
	}

	// PE: "MZ" DOS stub; e_lfanew at 0x3C points at "PE\0\0", followed by the
	// COFF Machine field.
	if len(data) >= 2 && data[0] == 'M' && data[1] == 'Z' {
		return "windows", peMachineArch(data), true
	}
	return "", "", false
}

// peMachineArch decodes the COFF Machine field of a PE image. It returns "" for
// a truncated, malformed or unrecognised image.
func peMachineArch(data []byte) string {
	if len(data) < 0x40 {
		return ""
	}
	peOff := int64(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	// Bound with int64 so a corrupt e_lfanew near 2^32 cannot overflow.
	if peOff < 0 || peOff+6 > int64(len(data)) {
		return ""
	}
	if string(data[peOff:peOff+4]) != "PE\x00\x00" {
		return ""
	}
	switch binary.LittleEndian.Uint16(data[peOff+4 : peOff+6]) {
	case 0x8664: // IMAGE_FILE_MACHINE_AMD64
		return "amd64"
	case 0xAA64: // IMAGE_FILE_MACHINE_ARM64
		return "arm64"
	}
	return ""
}
