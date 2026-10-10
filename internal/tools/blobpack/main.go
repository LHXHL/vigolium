// Command blobpack zstd-compresses a Bun-compiled helper executable for
// embedding and writes its pin file. It is run by the Makefile staging targets
// and build/scripts/stage-audit-blob.sh, never at runtime.
//
//	go run ./internal/tools/blobpack -in RAW [-out BASE] [-platform os/arch] [-marker HASH]
//
// writes BASE.zst and BASE.pin (BASE defaults to RAW). The pin records the
// sha256 and size of the uncompressed executable (see internal/helperblob).
// Packing is content-addressed: when BASE.pin already pins RAW's hash and
// BASE.zst exists, nothing is rewritten, so the target is cheap to call before
// every build.
//
//	go run ./internal/tools/blobpack pins -name vigolium-audit -go-out FILE -asset-dir DIR os/arch=RAW...
//
// generates the pins_gen.go table for the opt-in `audit_external` build and
// writes the download assets <name>_<sha12>_<os>_<arch>.zst into DIR.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"go/format"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/internal/helperblob"
)

func main() {
	var err error
	if len(os.Args) > 1 && os.Args[1] == "pins" {
		err = runPins(os.Args[2:])
	} else {
		err = runPack(os.Args[1:])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[blobpack] %v\n", err)
		os.Exit(1)
	}
}

func runPack(args []string) error {
	fs := flag.NewFlagSet("blobpack", flag.ContinueOnError)
	in := fs.String("in", "", "raw helper executable to pack (required)")
	out := fs.String("out", "", "output base path; writes BASE.zst and BASE.pin (default: -in)")
	platform := fs.String("platform", "", "assert the executable targets this os/arch (e.g. linux/amd64)")
	marker := fs.String("marker", "", "source fingerprint to record in the pin when the executable contains it verbatim")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("-in is required")
	}
	base := *out
	if base == "" {
		base = *in
	}
	res, err := pack(*in, base, *platform, *marker)
	if err != nil {
		return err
	}
	fmt.Println(res)
	return nil
}

// pack writes base.zst and base.pin for the executable at in and returns a
// one-line summary.
func pack(in, base, wantPlatform, marker string) (string, error) {
	raw, err := os.ReadFile(in)
	if err != nil {
		return "", err
	}
	pin, err := describe(raw, wantPlatform, marker)
	if err != nil {
		return "", fmt.Errorf("%s: %w", in, err)
	}
	pinPath, zstPath := base+".pin", base+".zst"
	newPin, err := pin.Marshal()
	if err != nil {
		return "", err
	}

	if old, err := os.ReadFile(pinPath); err == nil {
		if prev, perr := helperblob.ParsePin(old); perr == nil && prev.SHA256 == pin.SHA256 && prev.Size == pin.Size {
			if st, serr := os.Stat(zstPath); serr == nil && st.Size() > 0 {
				if !bytes.Equal(old, newPin) {
					if err := writeAtomic(pinPath, newPin); err != nil {
						return "", err
					}
				}
				return fmt.Sprintf("[blobpack] %s is current (sha256 %s, %s)", filepath.Base(zstPath), pin.Short(), ratio(pin.Size, st.Size())), nil
			}
		}
	}

	// Drop the old pin first: if packing dies half way, the build then fails
	// on a missing pin instead of embedding a new .zst under an old pin.
	_ = os.Remove(pinPath)
	var buf bytes.Buffer
	if err := helperblob.Compress(&buf, bytes.NewReader(raw)); err != nil {
		return "", fmt.Errorf("compress %s: %w", in, err)
	}
	// Round-trip before anything is written: the runtime would refuse a
	// mismatching blob anyway, but here the failure names the build step.
	sum, n, err := helperblob.Decompress(io.Discard, bytes.NewReader(buf.Bytes()), pin.Size)
	if err != nil {
		return "", fmt.Errorf("round-trip check failed for %s: %w", in, err)
	}
	if sum != pin.SHA256 || n != pin.Size {
		return "", fmt.Errorf("round-trip check failed for %s: got sha256 %s (%d bytes)", in, sum, n)
	}
	if err := writeAtomic(zstPath, buf.Bytes()); err != nil {
		return "", err
	}
	if err := writeAtomic(pinPath, newPin); err != nil {
		return "", err
	}
	return fmt.Sprintf("[blobpack] packed %s -> %s (sha256 %s, %s)", filepath.Base(in), zstPath, pin.Short(), ratio(pin.Size, int64(buf.Len()))), nil
}

// describe builds the pin for raw, enforcing the platform assertion and
// recording marker only when raw carries it.
func describe(raw []byte, wantPlatform, marker string) (helperblob.Pin, error) {
	if len(raw) < 1<<20 {
		return helperblob.Pin{}, fmt.Errorf("only %d bytes; not a real helper executable (stub or LFS pointer?)", len(raw))
	}
	sum := sha256.Sum256(raw)
	pin := helperblob.Pin{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(raw))}
	goos, goarch, ok := helperblob.DetectPlatform(raw)
	if ok && goarch != "" {
		pin.Platform = goos + "/" + goarch
	}
	if wantPlatform != "" && pin.Platform != wantPlatform {
		got := pin.Platform
		if got == "" {
			got = "an unrecognised format"
		}
		return helperblob.Pin{}, fmt.Errorf("built for %s, expected %s: refusing to stage a wrong-platform helper", got, wantPlatform)
	}
	if marker != "" {
		if bytes.Contains(raw, []byte(marker)) {
			pin.SourceHash = marker
		} else {
			fmt.Fprintf(os.Stderr, "[blobpack] warning: executable does not contain source fingerprint %s; pin records none\n", marker)
		}
	}
	return pin, nil
}

func runPins(args []string) error {
	fs := flag.NewFlagSet("blobpack pins", flag.ContinueOnError)
	name := fs.String("name", "vigolium-audit", "helper name used in asset file names")
	goOut := fs.String("go-out", "", "path of the generated Go pins file (required)")
	pkg := fs.String("package", "bin", "package name for the generated file")
	assetDir := fs.String("asset-dir", "", "directory to write <name>_<sha12>_<os>_<arch>.zst download assets into (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *goOut == "" || *assetDir == "" || fs.NArg() == 0 {
		return fmt.Errorf("usage: blobpack pins -go-out FILE -asset-dir DIR os/arch=RAW [os/arch=RAW]")
	}
	if err := os.MkdirAll(*assetDir, 0o755); err != nil {
		return err
	}
	pins := map[string]helperblob.Pin{}
	for _, arg := range fs.Args() {
		platform, path, ok := strings.Cut(arg, "=")
		if !ok {
			return fmt.Errorf("argument %q is not os/arch=PATH", arg)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		pin, err := describe(raw, platform, "")
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		var buf bytes.Buffer
		if err := helperblob.Compress(&buf, bytes.NewReader(raw)); err != nil {
			return err
		}
		goos, goarch, _ := strings.Cut(platform, "/")
		asset := filepath.Join(*assetDir, fmt.Sprintf("%s_%s_%s_%s.zst", *name, pin.Short(), goos, goarch))
		if err := writeAtomic(asset, buf.Bytes()); err != nil {
			return err
		}
		fmt.Printf("[blobpack] asset %s (%s)\n", asset, ratio(pin.Size, int64(buf.Len())))
		pins[goos+"_"+goarch] = pin
	}
	src, err := renderPins(*pkg, pins)
	if err != nil {
		return err
	}
	if err := writeAtomic(*goOut, src); err != nil {
		return err
	}
	fmt.Printf("[blobpack] wrote %s (%d platforms)\n", *goOut, len(pins))
	return nil
}

// renderPins renders the generated pins table. The file registers itself in
// init so the hand-written audit_external code compiles without it.
func renderPins(pkg string, pins map[string]helperblob.Pin) ([]byte, error) {
	keys := make([]string, 0, len(pins))
	for k := range pins {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "// Code generated by internal/tools/blobpack; DO NOT EDIT.\n\n//go:build audit_external\n\npackage %s\n\n", pkg)
	b.WriteString("import \"github.com/vigolium/vigolium/internal/helperblob\"\n\n")
	b.WriteString("func init() {\n\texternalPins = map[string]helperblob.Pin{\n")
	for _, k := range keys {
		p := pins[k]
		fmt.Fprintf(&b, "\t\t%q: {SHA256: %q, Size: %d, Platform: %q},\n", k, p.SHA256, p.Size, p.Platform)
	}
	b.WriteString("\t}\n}\n")
	return format.Source([]byte(b.String()))
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return nil
}

func ratio(raw, packed int64) string {
	if packed <= 0 {
		return "n/a"
	}
	return fmt.Sprintf("%d -> %d bytes, %.2fx", raw, packed, float64(raw)/float64(packed))
}
