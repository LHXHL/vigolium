//go:build linux && arm64 && !jstangle_stub

package deparos

import (
	_ "embed"
)

// JSTangleBinaryZst is the zstd-compressed jstangle helper and JSTangleBinaryPin
// its pin (sha256 and size of the uncompressed executable). Both are written by
// internal/tools/blobpack when the Makefile stages the helper
// (`make ensure-jstangle`, `make pack-jstangle`); see internal/helperblob.
//
//go:embed jstangle/jstangle-linux-arm64.zst
var JSTangleBinaryZst []byte

//go:embed jstangle/jstangle-linux-arm64.pin
var JSTangleBinaryPin []byte

const JSTangleBinaryName = "jstangle"
