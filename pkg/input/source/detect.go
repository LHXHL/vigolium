package source

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/burpscope"
	"github.com/vigolium/vigolium/pkg/input/formats/detect"
	"github.com/vigolium/vigolium/pkg/input/formats/har"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/formats/urls"
	"github.com/vigolium/vigolium/pkg/input/formats/wsdl"
)

// DetectHeadBytes is how much of a file DetectFormat reads. Every format's
// signal sits in its first few lines (a JSON/YAML/XML root, the first JSONL
// record, the first request line), so detection never reads a whole capture.
const DetectHeadBytes = 64 << 10

// detectMinScore is the score a sniffer must reach to displace the URL-list
// default. The urls fallback scores below it on purpose: it is what is left
// when nothing more specific matched.
const detectMinScore = 50

// Sniff scores how strongly head (the first DetectHeadBytes of a file) looks
// like one input format. name is the file's base name, for the few formats
// whose extension is a real signal. 0 means "not this format", 100 "certain";
// reason is a short human explanation logged with the detection.
type Sniff func(head []byte, name string) (score int, reason string)

// Detection is the outcome of DetectFormat.
type Detection struct {
	// Format is the canonical registry name of the winning format, "urls" when
	// only the URL-list fallback matched, or "" when nothing did.
	Format string
	Score  int
	Reason string
	// Candidates are every format that scored above zero, best first, so an
	// error can name the closest alternative when the winner fails to parse.
	Candidates []string
}

// Detected reports whether a specific (non-URL-list) format won.
func (d Detection) Detected() bool { return d.Format != "" && d.Format != "urls" }

// DetectFormat reads the head of the file at path and returns the format whose
// sniffer scores highest. Ties go to the earlier formatRegistry row. It reads
// at most DetectHeadBytes, never the whole file.
func DetectFormat(path string) (Detection, error) {
	head, err := readHead(path, DetectHeadBytes)
	if err != nil {
		return Detection{}, err
	}
	return DetectFormatHead(head, filepath.Base(path)), nil
}

// DetectFormatHead runs every registry sniffer over head. It is the content-only
// form of DetectFormat for callers that already hold the bytes (an uploaded
// body, a pasted string). Binary content detects as nothing.
func DetectFormatHead(head []byte, name string) Detection {
	head = bytes.TrimPrefix(head, []byte("\xef\xbb\xbf"))
	if len(bytes.TrimSpace(head)) == 0 || bytes.IndexByte(head, 0) >= 0 {
		return Detection{}
	}
	type scored struct {
		format string
		score  int
		reason string
		order  int
	}
	var hits []scored
	for i, e := range formatRegistry {
		if e.sniff == nil {
			continue
		}
		if s, r := e.sniff(head, name); s > 0 {
			hits = append(hits, scored{e.canonical, s, r, i})
		}
	}
	if len(hits) == 0 {
		return Detection{}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].score != hits[j].score {
			return hits[i].score > hits[j].score
		}
		return hits[i].order < hits[j].order
	})
	det := Detection{Candidates: make([]string, 0, len(hits))}
	for _, h := range hits {
		det.Candidates = append(det.Candidates, h.format)
	}
	best := hits[0]
	if best.score >= detectMinScore || best.format == "urls" {
		det.Format, det.Score, det.Reason = best.format, best.score, best.reason
	}
	return det
}

// readHead returns up to n bytes from the start of the file at path.
func readHead(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readHeadFrom(f, n)
}

// readHeadFrom reads at most n bytes from r.
func readHeadFrom(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	read, err := io.ReadFull(r, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return buf[:read], nil
}

// headLines splits head into trimmed lines. When the head filled the whole
// read window its last line may be cut mid-way, so it is dropped.
func headLines(head []byte) []string {
	s := string(head)
	if len(head) >= DetectHeadBytes {
		if i := strings.LastIndexByte(s, '\n'); i >= 0 {
			s = s[:i]
		}
	}
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	return lines
}

// firstContentLine returns the first non-blank line that is not a `#` comment.
func firstContentLine(head []byte) string {
	for _, ln := range headLines(head) {
		if urls.IsTargetLine(ln) {
			return ln
		}
	}
	return ""
}

// jsonRoot reports whether head is (the start of) a JSON object.
func jsonRoot(head []byte) bool {
	t := bytes.TrimLeft(head, " \t\r\n")
	return len(t) > 0 && t[0] == '{'
}

// --- per-format sniffers (wired into formatRegistry in file.go) ---

// urlLineStats counts the target lines in head (non-blank, non-comment) and
// how many of them the URL-list parser accepts. Shared by the urls sniffer and
// the "mostly not URLs" guard so both use the parser's own rule.
func urlLineStats(head []byte) (targets, parsed int) {
	for _, ln := range headLines(head) {
		if !urls.IsTargetLine(ln) {
			continue
		}
		targets++
		if _, err := httpmsg.GetRawRequestFromURL(ln); err == nil {
			parsed++
		}
	}
	return targets, parsed
}

// sniffURLList is the fallback: it never reaches detectMinScore, so it only
// wins when nothing more specific matched.
func sniffURLList(head []byte, _ string) (int, string) {
	targets, parsed := urlLineStats(head)
	if targets == 0 || parsed*2 <= targets {
		return 0, ""
	}
	return 10, fmt.Sprintf("%d of %d lines are URLs", parsed, targets)
}

func sniffHAR(head []byte, _ string) (int, string) {
	if har.IsHAR(head) {
		return 95, "JSON log object with version and entries/creator"
	}
	return 0, ""
}

func sniffPostman(head []byte, _ string) (int, string) {
	if !jsonRoot(head) {
		return 0, ""
	}
	if bytes.Contains(head, []byte(`"_postman_id"`)) {
		return 95, "info._postman_id"
	}
	if bytes.Contains(head, []byte("schema.getpostman.com")) {
		return 95, "info.schema is a getpostman.com collection schema"
	}
	if bytes.Contains(head, []byte(`"info"`)) && bytes.Contains(head, []byte(`"item"`)) &&
		bytes.Contains(head, []byte(`"request"`)) {
		return 60, "info + item[].request collection shape"
	}
	return 0, ""
}

var (
	// openAPIJSONKey is an "openapi"/"swagger" version key in a JSON document.
	openAPIJSONKey = regexp.MustCompile(`"(openapi|swagger)"\s*:\s*"[0-9]`)
	// openAPIYAMLKey is a top-level (unindented) openapi:/swagger: key.
	openAPIYAMLKey = regexp.MustCompile(`(?m)^(openapi|swagger)\s*:\s*['"]?[0-9]`)
)

func sniffOpenAPI(head []byte, _ string) (int, string) {
	// A complete document parses outright; a large spec is cut at the head
	// window, so fall back to the version key itself.
	if len(head) < DetectHeadBytes && openapi.IsOpenAPISpec(head) {
		return 100, "openapi/swagger version key"
	}
	if openAPIYAMLKey.Match(head) {
		return 90, "top-level openapi/swagger key"
	}
	if jsonRoot(head) && openAPIJSONKey.Match(head) {
		return 80, "openapi/swagger version key"
	}
	return 0, ""
}

func sniffBurpScope(head []byte, _ string) (int, string) {
	if !jsonRoot(head) {
		return 0, ""
	}
	if burpscope.Sniff(head) {
		return 95, "target.scope include/exclude rules"
	}
	// A large project config is cut at the head window, where Sniff's full
	// unmarshal cannot succeed.
	if len(head) >= DetectHeadBytes && bytes.Contains(head, []byte(`"target"`)) &&
		bytes.Contains(head, []byte(`"scope"`)) &&
		(bytes.Contains(head, []byte(`"include"`)) || bytes.Contains(head, []byte(`"exclude"`))) {
		return 70, "target.scope object"
	}
	return 0, ""
}

// burpXMLRoot matches an <items> root element after an optional XML prolog.
var burpXMLRoot = regexp.MustCompile(`^(<\?xml[^>]*\?>\s*)?(<!DOCTYPE[^>]*(\[[^\]]*\])?>\s*)?<items[\s>]`)

func sniffBurpXML(head []byte, _ string) (int, string) {
	t := bytes.TrimLeft(head, " \t\r\n")
	if !burpXMLRoot.Match(t) {
		return 0, ""
	}
	if bytes.Contains(t, []byte("burpVersion=")) {
		return 95, "<items burpVersion=…> root"
	}
	return 85, "<items> root"
}

func sniffWSDL(head []byte, _ string) (int, string) {
	if wsdl.IsWSDL(head) {
		return 95, "WSDL definitions root with a SOAP binding"
	}
	return 0, ""
}

// firstJSONRecord decodes the first non-blank line of head as a JSON object.
// A record longer than the head window cannot be decoded; ok is then false and
// the caller falls back to key matching on the raw line.
func firstJSONRecord(head []byte) (line string, rec map[string]json.RawMessage, ok bool) {
	line = firstContentLine(head)
	if !strings.HasPrefix(line, "{") {
		return "", nil, false
	}
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		return line, nil, false
	}
	return line, rec, true
}

func sniffNuclei(head []byte, _ string) (int, string) {
	line, rec, ok := firstJSONRecord(head)
	if line == "" {
		return 0, ""
	}
	if !ok {
		if strings.Contains(line, `"template-id"`) {
			return 85, "JSONL record with template-id"
		}
		return 0, ""
	}
	if _, has := rec["template-id"]; has {
		if _, m := rec["matched-at"]; m {
			return 95, "JSONL record with template-id and matched-at"
		}
		if _, i := rec["info"]; i {
			return 95, "JSONL record with template-id and info"
		}
		return 85, "JSONL record with template-id"
	}
	// The parser also takes the bare {url, request:{raw}} shape.
	if _, has := rec["url"]; has {
		var req struct {
			Raw string `json:"raw"`
		}
		if raw, ok := rec["request"]; ok && json.Unmarshal(raw, &req) == nil && req.Raw != "" {
			return 70, "JSONL record with url and request.raw"
		}
	}
	return 0, ""
}

func sniffDeparos(head []byte, _ string) (int, string) {
	line, rec, ok := firstJSONRecord(head)
	if line == "" {
		return 0, ""
	}
	if !ok {
		if strings.Contains(line, `"found_by"`) && strings.Contains(line, `"url"`) {
			return 80, "JSONL record with url and found_by"
		}
		return 0, ""
	}
	if _, has := rec["url"]; !has {
		return 0, ""
	}
	if _, has := rec["found_by"]; has {
		return 90, "JSONL record with url and found_by"
	}
	_, status := rec["status_code"]
	_, depth := rec["depth"]
	if status && depth {
		return 75, "JSONL record with url, status_code and depth"
	}
	return 0, ""
}

// curlLine matches a line that is a curl command, with an optional shell prompt.
var curlLine = regexp.MustCompile(`(?m)^\s*(\$\s+)?curl\s+\S`)

func sniffCurl(head []byte, name string) (int, string) {
	first := strings.TrimSpace(strings.TrimPrefix(firstContentLine(head), "$ "))
	if strings.HasPrefix(first, "curl ") || strings.HasPrefix(first, "curl\t") {
		return 95, "first line is a curl command"
	}
	if !curlLine.Match(head) {
		return 0, ""
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".curl":
		return 90, ".curl file with a curl command"
	case ".sh", ".bash", ".zsh", ".md", ".markdown", ".txt":
		return 60, "script/markdown containing curl commands"
	}
	return 0, ""
}

// rawRequestLine matches an HTTP/1.x request line ("GET /x HTTP/1.1").
var rawRequestLine = regexp.MustCompile(`^[A-Z]{3,10} \S+ HTTP/[0-9](\.[0-9])?$`)

func sniffBurpRaw(head []byte, _ string) (int, string) {
	if !rawRequestLine.MatchString(firstContentLine(head)) {
		return 0, ""
	}
	if _, _, ok := detect.FindBurpSeparator(string(head)); ok {
		return 92, "raw HTTP request with a *** response separator"
	}
	return 90, "raw HTTP request line"
}

// ---------------------------------------------------------------------------
// Never-silent URL-list guard
// ---------------------------------------------------------------------------

// UnparsedInputError is returned when a file read as a URL list is mostly not
// URLs. Reading it anyway would turn its lines into junk targets (or none), so
// the run stops and names the closest format instead.
type UnparsedInputError struct {
	Path      string
	Lines     int    // non-blank, non-comment lines examined
	Failed    int    // of those, lines the URL parser rejected
	Candidate string // closest other format, "" when none scored
	Explicit  bool   // the URL-list format was requested explicitly
}

// Code is the machine error code (pkg/apicontract vocabulary).
func (e *UnparsedInputError) Code() string { return "input_unparsed" }

func (e *UnparsedInputError) Error() string {
	var b strings.Builder
	what := "is not a URL list"
	if e.Explicit {
		what = "was given as a URL list but is not one"
	}
	fmt.Fprintf(&b, "input %q %s: %d of %d non-comment lines are not URLs",
		e.Path, what, e.Failed, e.Lines)
	if e.Candidate != "" {
		fmt.Fprintf(&b, "; it looks closest to %s — pass -I %s", e.Candidate, e.Candidate)
	} else {
		fmt.Fprintf(&b, "; pass -I <format> (supported: %s)", SupportedFormats())
	}
	return b.String()
}

// CheckURLListContent applies the never-silent URL-list rule to content that
// is about to be read as a URL list: it returns an *UnparsedInputError when more
// than half of its non-comment lines are not URLs, naming the closest format.
// name labels the input in the error. Only the first DetectHeadBytes are
// examined, like DetectFormat.
func CheckURLListContent(name string, content []byte, explicit bool) error {
	head := content
	if len(head) > DetectHeadBytes {
		head = head[:DetectHeadBytes]
	}
	return checkURLListHead(name, head, DetectFormatHead(head, ""), explicit)
}

// checkURLListHead fails when more than half of the target lines in head are
// rejected by the URL parser. An empty or all-comment file passes (it simply
// yields nothing, as before).
func checkURLListHead(path string, head []byte, det Detection, explicit bool) error {
	targets, parsed := urlLineStats(head)
	failed := targets - parsed
	if targets == 0 || failed*2 <= targets {
		return nil
	}
	candidate := ""
	for _, c := range det.Candidates {
		if c != "urls" {
			candidate = c
			break
		}
	}
	return &UnparsedInputError{Path: path, Lines: targets, Failed: failed, Candidate: candidate, Explicit: explicit}
}
