//go:build !audit_external

package bin

import (
	"io/fs"
	"runtime"
	"strings"
	"testing"
)

// TestEmbeddedAuditBlobMatchesHost guards the host build path: whatever
// vigolium-audit blob `make build` embedded must run on the platform this
// test binary was built for. On a fresh clone nothing is embedded, so the
// check is skipped. This catches a mis-staged host blob (e.g. a darwin blob
// left in _bin while building on linux) at `make test` time.
func TestEmbeddedAuditBlobMatchesHost(t *testing.T) {
	pin, err := (&embeddedSource{}).pin()
	if err != nil || pin.Size < minBinarySize {
		t.Skip("no real vigolium-audit binary embedded (stub or fresh clone)")
	}
	if pin.Platform == "" {
		t.Fatalf("embedded vigolium-audit pin records no platform: the packer did not recognise the executable format")
	}
	goos, goarch, _ := strings.Cut(pin.Platform, "/")
	if goos != runtime.GOOS || goarch != runtime.GOARCH {
		t.Fatalf("embedded vigolium-audit blob targets %s but this build is %s/%s — wrong host blob staged in _bin/",
			pin.Platform, runtime.GOOS, runtime.GOARCH)
	}
}

// TestEmbedCarriesOnlyCompressedBlob: `//go:embed all:_bin` embeds whatever
// sits in _bin, so a raw vigolium-audit left there by an older checkout or a
// stray copy would ship uncompressed (~65 MiB) next to the .zst. Only the
// packed blob, its pin and the git placeholders may be embedded.
func TestEmbedCarriesOnlyCompressedBlob(t *testing.T) {
	allowed := map[string]bool{
		"_bin/.gitkeep":   true,
		"_bin/.gitignore": true,
		embeddedBlobName:  true,
		embeddedPinName:   true,
	}
	err := fs.WalkDir(binFS, "_bin", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && !allowed[path] {
			t.Errorf("%s is embedded; only the zstd blob and its pin may live in pkg/audit/bin/_bin (run `make ensure-audit` to repack)", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
