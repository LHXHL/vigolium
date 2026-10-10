package bin

import (
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/vigolium/vigolium/internal/helperblob"
)

// ErrBinaryPlatformMismatch is returned when the embedded vigolium-audit blob
// targets a different OS/arch than the running process. This indicates a
// release packaging bug: the wrong-platform audit binary was staged into the
// embed path when vigolium was cross-compiled. See build/scripts/
// stage-audit-blob.sh and the per-target goreleaser pre-hook.
var ErrBinaryPlatformMismatch = errors.New("vigolium-audit binary platform mismatch")

// detectBlobPlatform inspects the leading bytes of an executable blob and
// reports the GOOS/GOARCH it targets, matched to Go's naming (amd64/arm64).
// ok is false when the format is unrecognized — callers must not treat an
// unknown format as a mismatch, only a confidently-decoded foreign platform.
// The decoder is shared with the stage-time packer (internal/helperblob),
// which records the result in the helper's pin.
func detectBlobPlatform(data []byte) (goos, goarch string, ok bool) {
	return helperblob.DetectPlatform(data)
}

// verifyPinForHost is verifyBlobForHost for a packed helper: the platform was
// decoded from the executable header at stage time and recorded in the pin,
// whose sha256 binds it to the bytes that will be installed. An empty
// platform (unrecognized format at pack time) passes, as in verifyBlobForHost.
func verifyPinForHost(pin helperblob.Pin) error {
	if pin.Platform == "" {
		return nil
	}
	goos, goarch, _ := strings.Cut(pin.Platform, "/")
	return checkPlatform(goos, goarch)
}

// verifyBlobForHost confirms the embedded vigolium-audit blob targets the
// platform this binary is running on. It returns ErrBinaryPlatformMismatch
// (wrapped with detail) when the blob is for a different OS/arch, converting a
// would-be "exec format error" into an actionable report. An unrecognized
// format returns nil — the guard never blocks on uncertainty; a genuinely
// broken blob will surface its own exec error downstream.
func verifyBlobForHost(data []byte) error {
	goos, goarch, ok := detectBlobPlatform(data)
	if !ok {
		return nil
	}
	return checkPlatform(goos, goarch)
}

func checkPlatform(goos, goarch string) error {
	if goos != runtime.GOOS || (goarch != "" && goarch != runtime.GOARCH) {
		return fmt.Errorf(
			"%w: vigolium-audit helper targets %s but this build runs on %s/%s — the wrong-platform audit binary was packaged at release time, please report this",
			ErrBinaryPlatformMismatch, platformLabel(goos, goarch), runtime.GOOS, runtime.GOARCH)
	}
	return nil
}

func platformLabel(goos, goarch string) string {
	if goarch == "" {
		return goos + "/(unknown arch)"
	}
	return goos + "/" + goarch
}
