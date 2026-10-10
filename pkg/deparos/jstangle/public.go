package jstangle

import (
	"sync"

	"github.com/vigolium/vigolium/internal/helperblob"
	deparospresets "github.com/vigolium/vigolium/internal/resources/deparos"
)

// embeddedBlob is the zstd-compressed helper and embeddedPinData its pin
// (sha256 and size of the uncompressed executable). Tests swap both through
// setEmbeddedForTest.
var (
	embeddedBlob    = deparospresets.JSTangleBinaryZst
	embeddedPinData = deparospresets.JSTangleBinaryPin
	binaryName      = deparospresets.JSTangleBinaryName

	embeddedPinOnce sync.Once
	embeddedPinVal  helperblob.Pin
	embeddedPinErr  error
)

// embeddedPin parses the embedded pin once.
func embeddedPin() (helperblob.Pin, error) {
	embeddedPinOnce.Do(func() {
		embeddedPinVal, embeddedPinErr = helperblob.ParsePin(embeddedPinData)
	})
	return embeddedPinVal, embeddedPinErr
}

// isEmbeddedBinaryValid returns true only when a real helper was embedded: a
// non-trivial compressed payload (the stub embeds nothing; a Git LFS pointer is
// a few hundred bytes) and a pin that parses.
func isEmbeddedBinaryValid() bool {
	if len(embeddedBlob) <= 1024 {
		return false
	}
	_, err := embeddedPin()
	return err == nil
}
