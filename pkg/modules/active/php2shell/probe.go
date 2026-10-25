package php2shell

import (
	"bytes"
	"fmt"
)

// The request shapes below are byte-for-byte those of the Assetnote
// php2shell-scanner (scanner.py): a 42-byte multipart control with boundary
// "x", then probes with an EMPTY boundary whose parts each carry a field name
// nested nestedKeys levels deep, padded with "x:" header lines to the size.

const (
	controlBoundary = "x"
	controlBody     = "--x\nContent-Disposition:name=a;filename=\n\n"
	probeBoundary   = ""
	nestedKeys      = 62

	// maxEvidenceBytes caps the response kept on a result, and the request body
	// head kept before the elision marker.
	maxEvidenceBytes = 2048
)

type probeSpec struct {
	sizeMiB int
	parts   int
}

// probes escalate from 1 to 20 MiB; probing stops at the first signal.
var probes = []probeSpec{{1, 4000}, {8, 1020}, {20, 1020}}

// buildProbeBody returns a sizeMiB multipart body of parts nested-key parts.
func buildProbeBody(sizeMiB, parts int) []byte {
	size := sizeMiB << 20
	name := "a[]" + string(bytes.Repeat([]byte("[a]"), nestedKeys))
	part := []byte("--\nContent-Disposition:name=" + name + ";filename=\n\n")
	base := bytes.Repeat(part, parts)
	if size < len(base) {
		panic(fmt.Sprintf("php2shell probe of %d bytes cannot hold %d parts (%d bytes)", size, parts, len(base)))
	}
	filler := (size - len(base)) / 3

	var buf bytes.Buffer
	buf.Grow(3 + filler*3 + len(base))
	buf.WriteString("--\n")
	for range filler {
		buf.WriteString("x:\n")
	}
	buf.Write(base[3:])
	body := buf.Bytes()
	return body[:len(body)-1]
}
