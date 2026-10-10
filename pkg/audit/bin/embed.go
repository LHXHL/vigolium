//go:build !audit_external

// Package bin provides the vigolium-audit host binary to vigolium and
// installs it into a per-user cache directory on first use.
//
// Default builds embed the helper. It is built from platform/vigolium-audit/
// by `make update-audit`, then zstd-compressed by internal/tools/blobpack into
// _bin/vigolium-audit.zst with its pin _bin/vigolium-audit.pin (sha256 and
// size of the UNCOMPRESSED executable, see internal/helperblob). Cross-compiling
// vigolium requires staging the matching target's blob before `go build`; the
// release does this per target via the goreleaser pre-hook
// build/scripts/stage-audit-blob.sh (builds run with --parallelism 1 because
// the embed path is shared). The pin's platform guards against a
// wrong-platform blob slipping through at runtime.
//
// Builds with `-tags audit_external` embed nothing and download the pinned
// helper on first use instead (external.go).
package bin

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sync"

	"github.com/vigolium/vigolium/internal/helperblob"
)

// binFS holds whatever lives under _bin at compile time. `all:` lets the
// embed directive match an empty _bin (only the tracked .gitkeep) on
// fresh clones — missing-binary surfaces as a runtime extract error
// rather than a build failure. Only the compressed blob and its pin may live
// here; TestEmbedCarriesOnlyCompressedBlob fails if a raw executable was
// staged, since `all:_bin` would silently embed it uncompressed.
//
//go:embed all:_bin
var binFS embed.FS

const (
	embeddedBlobName = "_bin/vigolium-audit.zst"
	embeddedPinName  = "_bin/vigolium-audit.pin"
)

var helperSource source = &embeddedSource{}

// embeddedSource serves the compressed helper from binFS.
type embeddedSource struct {
	once sync.Once
	p    helperblob.Pin
	err  error
}

func (*embeddedSource) kind() string { return SourceEmbedded }

func (s *embeddedSource) pin() (helperblob.Pin, error) {
	s.once.Do(func() {
		data, err := binFS.ReadFile(embeddedPinName)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				s.err = fmt.Errorf("%w: run `make build-audit` and rebuild vigolium", ErrBinaryMissing)
				return
			}
			s.err = fmt.Errorf("read embedded vigolium-audit pin: %w", err)
			return
		}
		if st, err := fs.Stat(binFS, embeddedBlobName); err != nil || st.Size() == 0 {
			s.err = fmt.Errorf("%w: pin present but %s is missing; run `make build-audit` and rebuild vigolium", ErrBinaryMissing, embeddedBlobName)
			return
		}
		s.p, s.err = helperblob.ParsePin(data)
	})
	return s.p, s.err
}

func (*embeddedSource) open(_ context.Context, _ helperblob.Pin) (io.ReadCloser, error) {
	f, err := binFS.Open(embeddedBlobName)
	if err != nil {
		return nil, fmt.Errorf("read embedded vigolium-audit: %w", err)
	}
	return f, nil
}

// ready: an embedded blob can always be installed once its pin parsed.
func (*embeddedSource) ready(helperblob.Pin) bool { return true }

func (*embeddedSource) origin(helperblob.Pin) string { return "embedded" }
