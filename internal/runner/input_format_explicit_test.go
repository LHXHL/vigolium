package runner

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/types"
)

// -I given explicitly reaches the input source: a -T file passed with an
// explicit -I urls is read as a URL list (and refused, naming the format it
// resembles) instead of being content-sniffed into a HAR.
func TestNewHonoursExplicitInputMode(t *testing.T) {
	har := filepath.Join("..", "..", "pkg", "input", "source", "testdata", "detect", "capture.har")

	opts := types.DefaultOptions()
	opts.Silent = true
	opts.TargetsFilePaths = []string{har}
	opts.InputFileMode = "urls"
	opts.InputFileModeExplicit = true
	_, err := New(opts)
	if err == nil || !strings.Contains(err.Error(), "-I har") {
		t.Fatalf("explicit -I urls over a HAR: err = %v, want the input_unparsed hint naming -I har", err)
	}
}
