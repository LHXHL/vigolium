package source

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/formats/wsdl"
)

const detectFixtures = "testdata/detect"

// TestDetectFormatFixtures runs the detector over one fixture per format, with
// the right extension, a misleading one (five different formats as .json) and
// none, and checks that the detected parser actually yields a record.
func TestDetectFormatFixtures(t *testing.T) {
	cases := []struct {
		file string
		want string
	}{
		{"capture.har", "har"},
		{"har_as.json", "har"},
		{"har_noext", "har"},
		{"collection.json", "postman"},
		{"openapi.json", "openapi"},
		{"openapi.yaml", "openapi"},
		{"spec_noext", "openapi"},
		{"swagger.json", "openapi"},
		{"scope.json", "burpscope"},
		{"burp.xml", "burpxml"},
		{"burp_as.json", "burpxml"},
		{"service.wsdl", "wsdl"},
		{"nuclei.jsonl", "nuclei"},
		{"nuclei_as.json", "nuclei"},
		{"deparos.jsonl", "deparos"},
		{"deparos_as.json", "deparos"},
		{"commands.sh", "curl"},
		{"login.curl", "curl"},
		{"curl_noext", "curl"},
		{"request.req", "burpraw"},
		{"request_noext", "burpraw"},
		{"pair.txt", "burpraw"},
		{"targets.txt", "urls"},
		{"targets_as.json", "urls"},
		{"notes.md", ""},
		{"unknown.json", ""},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			path := filepath.Join(detectFixtures, c.file)
			det, err := DetectFormat(path)
			require.NoError(t, err)
			assert.Equal(t, c.want, det.Format, "reason=%q candidates=%v", det.Reason, det.Candidates)
			if c.want == "" {
				return
			}
			assert.NotEmpty(t, det.Reason)

			// The detected format must be the one NewFileSource picks, and it
			// must parse the fixture into at least one record.
			fs, err := NewFileSource(FileSourceConfig{FilePath: path, Format: "urls"})
			require.NoError(t, err)
			t.Cleanup(func() { _ = fs.Close() })
			assert.Equal(t, c.want, canonicalName(t, fs))
			switch p := fs.Format().(type) {
			case *openapi.Format:
				p.SetOpenAPIOptions(openapi.Options{UseSpecServers: true})
			case *wsdl.Format:
				p.SetWSDLOptions(wsdl.Options{EndpointURL: "https://example.test/soap"})
			}
			item, err := fs.Next(context.Background())
			require.NoError(t, err)
			require.NotNil(t, item)
		})
	}
}

// canonicalName maps a parser's Name() back to its registry row, since a few
// parsers name themselves differently from the canonical -I value.
func canonicalName(t *testing.T, fs *FileSource) string {
	t.Helper()
	info, ok := LookupFormat(fs.Format().Name())
	require.True(t, ok, "parser name %q must resolve", fs.Format().Name())
	return info.Name
}

// TestEveryFormatHasSniffer keeps DetectFormat total: a format added to the
// registry without a sniffer could only ever be reached with an explicit -I.
func TestEveryFormatHasSniffer(t *testing.T) {
	for _, e := range formatRegistry {
		assert.NotNil(t, e.sniff, "format %q has no sniffer", e.canonical)
	}
}

// countingReader records how many bytes were read through it.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// TestDetectReadsOnlyTheHead: detection must not read a large capture whole.
func TestDetectReadsOnlyTheHead(t *testing.T) {
	big := bytes.Repeat([]byte("https://example.test/path\n"), 200_000) // ~5 MiB
	cr := &countingReader{r: bytes.NewReader(big)}
	head, err := readHeadFrom(cr, DetectHeadBytes)
	require.NoError(t, err)
	assert.Len(t, head, DetectHeadBytes)
	assert.LessOrEqual(t, cr.n, DetectHeadBytes)
	assert.Equal(t, "urls", DetectFormatHead(head, "big.txt").Format)
}

// TestDetectTruncatedLargeSpec: a spec larger than the head window cannot be
// fully parsed from the head; the version key alone must still detect it.
func TestDetectTruncatedLargeSpec(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"openapi":"3.0.0","info":{"title":"big","version":"1"},"paths":{`)
	for i := 0; b.Len() < 2*DetectHeadBytes; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"/p` + strings.Repeat("x", 40) + string(rune('a'+i%26)) + `":{"get":{"responses":{"200":{"description":"ok"}}}}`)
	}
	b.WriteString("}}")
	path := filepath.Join(t.TempDir(), "big.json")
	require.NoError(t, os.WriteFile(path, []byte(b.String()), 0o644))
	det, err := DetectFormat(path)
	require.NoError(t, err)
	assert.Equal(t, "openapi", det.Format)
}

// TestDetectBinaryIsNothing: NUL bytes mean no text format applies.
func TestDetectBinaryIsNothing(t *testing.T) {
	assert.Equal(t, "", DetectFormatHead([]byte("\x00\x01{\"log\":{\"version\":\"1\",\"entries\":[]}}"), "x.har").Format)
	assert.Equal(t, "", DetectFormatHead(nil, "").Format)
}

// TestNewFileSourceRejectsMostlyNonURLs is the never-silent guard: a file read
// as a URL list whose lines are mostly not URLs fails with input_unparsed
// instead of becoming junk targets.
func TestNewFileSourceRejectsMostlyNonURLs(t *testing.T) {
	_, err := NewFileSource(FileSourceConfig{FilePath: filepath.Join(detectFixtures, "unknown.json"), Format: "urls"})
	var ue *UnparsedInputError
	require.True(t, errors.As(err, &ue), "got %v", err)
	assert.Equal(t, "input_unparsed", ue.Code())
	assert.Empty(t, ue.Candidate)
	assert.Contains(t, err.Error(), "supported:")
}

// TestNewFileSourceExplicitURLsSkipsDetection: -I urls given explicitly is
// never second-guessed into another parser, but a file that is mostly not URLs
// still fails, naming the format it resembles.
func TestNewFileSourceExplicitURLsSkipsDetection(t *testing.T) {
	_, err := NewFileSource(FileSourceConfig{
		FilePath: filepath.Join(detectFixtures, "capture.har"), Format: "urls", FormatExplicit: true,
	})
	var ue *UnparsedInputError
	require.True(t, errors.As(err, &ue), "got %v", err)
	assert.Equal(t, "har", ue.Candidate)
	assert.True(t, ue.Explicit)
	assert.Contains(t, err.Error(), "-I har")

	fs, err := NewFileSource(FileSourceConfig{
		FilePath: filepath.Join(detectFixtures, "targets.txt"), Format: "url", FormatExplicit: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = fs.Close() })
	assert.Equal(t, "urls", fs.Format().Name())
	assert.False(t, fs.Detection().Detected())
}

// TestNewFileSourceRecordsDetection exposes the detection for reporting.
func TestNewFileSourceRecordsDetection(t *testing.T) {
	fs, err := NewFileSource(FileSourceConfig{FilePath: filepath.Join(detectFixtures, "collection.json")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = fs.Close() })
	d := fs.Detection()
	assert.True(t, d.Detected())
	assert.Equal(t, "postman", d.Format)
	assert.Contains(t, d.Reason, "_postman_id")
}

// TestLookupFormatLegacyRESTNames: the REST ingest API's historical mode names
// are registry aliases, so REST and -I share one vocabulary.
func TestLookupFormatLegacyRESTNames(t *testing.T) {
	for alias, want := range map[string]string{
		"postman_collection": "postman",
		"http_archive":       "har",
		"url_file":           "urls",
		"swagger":            "openapi",
		"HAR":                "har",
	} {
		info, ok := LookupFormat(alias)
		require.True(t, ok, alias)
		assert.Equal(t, want, info.Name, alias)
	}
	_, ok := LookupFormat("postamn")
	assert.False(t, ok)
}
