package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/types"
)

func writeTargetFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

// TestSeedTargetsFromTargetFilesPopulatesTargets is the regression guard for the
// bug seedTargetsFromTargetFiles documents: a -T run left Options.Targets empty,
// so every target-seeded phase saw nothing while the banner read "Targets: N".
func TestSeedTargetsFromTargetFilesPopulatesTargets(t *testing.T) {
	path := writeTargetFile(t, "hosts.txt", "http://a.example.com\n\n# comment\nhttp://b.example.com\n")

	opts := &types.Options{TargetsFilePaths: []string{path}}
	require.NoError(t, seedTargetsFromTargetFiles(opts))

	assert.Equal(t, []string{"http://a.example.com", "http://b.example.com"}, opts.Targets)
	// Cleared so NewInputSource builds one TargetSource rather than a
	// TargetSource plus a FileSource over the same lines.
	assert.Empty(t, opts.TargetsFilePaths)
}

// TestSeedTargetsFromTargetFilesNoDoubleIngest locks the other half of that
// contract end to end: after seeding, the input source runner.New builds must
// yield each target exactly once. Leaving TargetsFilePaths set alongside the
// promoted Targets would ingest the whole file twice.
func TestSeedTargetsFromTargetFilesNoDoubleIngest(t *testing.T) {
	path := writeTargetFile(t, "hosts.txt", "http://a.example.com/\nhttp://b.example.com/\n")

	opts := &types.Options{TargetsFilePaths: []string{path}}
	require.NoError(t, seedTargetsFromTargetFiles(opts))

	src, err := source.NewInputSource(source.SourceConfig{
		Targets:   opts.Targets,
		FilePaths: opts.TargetsFilePaths,
		Format:    opts.InputFileMode,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = src.Close() })

	var hosts []string
	for {
		item, nextErr := src.Next(context.Background())
		if errors.Is(nextErr, io.EOF) {
			break
		}
		require.NoError(t, nextErr)
		hosts = append(hosts, item.Request.Service().Host())
	}
	assert.Equal(t, []string{"a.example.com", "b.example.com"}, hosts)
}

// TestSeedTargetsFromTargetFilesMergesWithCLITargets keeps -t and -T additive
// and de-duplicated: a URL named both ways is scanned once.
func TestSeedTargetsFromTargetFilesMergesWithCLITargets(t *testing.T) {
	path := writeTargetFile(t, "hosts.txt", "http://b.example.com\nhttp://a.example.com\n")

	opts := &types.Options{
		Targets:          []string{"http://a.example.com"},
		TargetsFilePaths: []string{path},
	}
	require.NoError(t, seedTargetsFromTargetFiles(opts))

	assert.Equal(t, []string{"http://a.example.com", "http://b.example.com"}, opts.Targets)
}

// TestSeedTargetsFromTargetFilesSkipsSpecInputMode protects the one -T shape
// that is NOT a target list: an explicit spec/export -I parses the file through
// that format's parser, whose records are not URLs a phase can seed from.
// Promoting them would replace a HAR parse with a line-by-line URL read.
func TestSeedTargetsFromTargetFilesSkipsSpecInputMode(t *testing.T) {
	path := writeTargetFile(t, "traffic.har", `{"log":{"entries":[]}}`)

	opts := &types.Options{
		TargetsFilePaths: []string{path},
		InputFileMode:    "har",
	}
	require.NoError(t, seedTargetsFromTargetFiles(opts))

	assert.Empty(t, opts.Targets)
	assert.Equal(t, []string{path}, opts.TargetsFilePaths)
}

// TestSeedTargetsFromTargetFilesPromotesBurpScope covers a Burp scope export.
// burpscope is a target-list format in the registry, so it promotes through the
// same predicate as a plain URL list rather than a special case here.
func TestSeedTargetsFromTargetFilesPromotesBurpScope(t *testing.T) {
	silent := globalSilent
	globalSilent = true
	t.Cleanup(func() { globalSilent = silent })

	path := writeTargetFile(t, "scope.json", `{"target":{"scope":{"advanced_mode":true,
	  "include":[{"enabled":true,"file":"^/.*","host":"^www\\.example\\.com$","port":"^443$","protocol":"https"}],
	  "exclude":[]}}}`)

	opts := &types.Options{
		TargetsFilePaths: []string{path},
		InputFileMode:    "burpscope",
	}
	require.NoError(t, seedTargetsFromTargetFiles(opts))

	assert.Equal(t, []string{"https://www.example.com/"}, opts.Targets)
	assert.Empty(t, opts.TargetsFilePaths)
}

// TestSeedTargetsFromTargetFilesEmptyFileKeepsPaths leaves an empty file to the
// callers that reject it by name, rather than clearing the paths and turning
// the run into a target-less DB scan.
func TestSeedTargetsFromTargetFilesEmptyFileKeepsPaths(t *testing.T) {
	path := writeTargetFile(t, "empty.txt", "\n# nothing\n")

	opts := &types.Options{TargetsFilePaths: []string{path}}
	require.NoError(t, seedTargetsFromTargetFiles(opts))

	assert.Empty(t, opts.Targets)
	assert.Equal(t, []string{path}, opts.TargetsFilePaths)
}

func TestSeedTargetsFromTargetFilesNoFilesIsNoop(t *testing.T) {
	opts := &types.Options{Targets: []string{"http://a.example.com"}}
	require.NoError(t, seedTargetsFromTargetFiles(opts))
	assert.Equal(t, []string{"http://a.example.com"}, opts.Targets)
}

// TestSeedTargetsFromStdinLines keeps a piped URL list accepting exactly what a
// -T file accepts — trimmed, blanks and `#` comments skipped, de-duplicated —
// so the two ways of handing vigolium a target list cannot drift apart.
func TestSeedTargetsFromStdinLines(t *testing.T) {
	opts := &types.Options{}
	seedTargetsFromStdinLines(opts, "http://a.example.com\n  http://b.example.com  \n\n# note\nhttp://a.example.com\n")

	assert.Equal(t, []string{"http://a.example.com", "http://b.example.com"}, opts.Targets)
}

func TestSeedTargetsFromStdinLinesEmpty(t *testing.T) {
	opts := &types.Options{}
	seedTargetsFromStdinLines(opts, "")
	assert.Empty(t, opts.Targets)
}

// TestSeedTargetsFromTargetFilesRecordsFileOrigin: promotion clears
// TargetsFilePaths, so anything downstream that needs to know the run was
// file-driven — the -P fan-out hint, which only ever splits a -T file — reads
// this flag instead.
func TestSeedTargetsFromTargetFilesRecordsFileOrigin(t *testing.T) {
	path := writeTargetFile(t, "hosts.txt", "http://a.example.com\nhttp://b.example.com\n")

	opts := &types.Options{TargetsFilePaths: []string{path}}
	require.NoError(t, seedTargetsFromTargetFiles(opts))
	assert.True(t, opts.TargetsSeededFromFile)

	// Not set when nothing was promoted.
	untouched := &types.Options{TargetsFilePaths: []string{path}, InputFileMode: "har"}
	require.NoError(t, seedTargetsFromTargetFiles(untouched))
	assert.False(t, untouched.TargetsSeededFromFile)
}

// TestTargetFileAndStdinAcceptTheSameList ties the two promotion paths to one
// line rule (isTargetLine). The contract is that `-T list.txt` and
// `cat list.txt | vigolium ...` seed identical targets; with an implementation
// on each side, only a test that runs both can hold them together.
func TestTargetFileAndStdinAcceptTheSameList(t *testing.T) {
	const list = "http://a.example.com\n  http://b.example.com  \n\n# a comment\nhttp://a.example.com\n"

	fromFile := &types.Options{TargetsFilePaths: []string{writeTargetFile(t, "hosts.txt", list)}}
	require.NoError(t, seedTargetsFromTargetFiles(fromFile))

	fromStdin := &types.Options{}
	seedTargetsFromStdinLines(fromStdin, list)

	assert.Equal(t, fromFile.Targets, fromStdin.Targets)
	assert.Equal(t, []string{"http://a.example.com", "http://b.example.com"}, fromStdin.Targets)
}

// A -T file of bare hostnames is the common recon hand-off, and it has to reach
// the phases as absolute URLs: the browser-based spidering phase fails each
// schemeless seed while probe and discovery scan the same list fine.
func TestSeedTargetsFromTargetFileNormalizesSchemelessLines(t *testing.T) {
	opts := &types.Options{TargetsFilePaths: []string{writeTargetFile(t, "bare.txt", "example.com\n")}}
	require.NoError(t, seedTargetsFromTargetFiles(opts))

	assert.Equal(t, []string{"http://example.com"}, opts.Targets)
}
