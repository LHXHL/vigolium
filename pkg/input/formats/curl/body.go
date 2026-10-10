package curl

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/pkg/input/formats/internal/multipartform"
)

// DataKind distinguishes curl's four body-data flavours, which differ only in
// how '@' and newlines are treated.
//
// This file is exported because `vigolium fuzz` accepts the same body flags
// directly and shares this implementation rather than restating it —
// --data-urlencode and -F have enough edge cases that two implementations
// would drift, and the difference would surface as a request curl and vigolium
// send differently.
type DataKind int

const (
	// DataAscii is -d/--data/--data-ascii: "@file" is read from disk and
	// newlines are stripped.
	DataAscii DataKind = iota
	// DataRaw is --data-raw (and --json): '@' carries no meaning.
	DataRaw
	// DataBinary is --data-binary: "@file" is read verbatim, newlines kept.
	DataBinary
	// DataURLEncode is --data-urlencode, whose argument has five forms —
	// see resolveURLEncode.
	DataURLEncode
)

// ResolveData turns one data flag's argument into the literal bytes that go
// into the body (or, under -G, the query string).
func ResolveData(v string, kind DataKind) (string, error) {
	switch kind {
	case DataRaw:
		return v, nil

	case DataAscii, DataBinary:
		if !strings.HasPrefix(v, "@") {
			return v, nil
		}
		content, err := readDataFile(strings.TrimPrefix(v, "@"))
		if err != nil {
			return "", err
		}
		if kind == DataAscii {
			// curl strips newlines and carriage returns for --data.
			content = strings.NewReplacer("\n", "", "\r", "").Replace(content)
		}
		return content, nil

	case DataURLEncode:
		return resolveURLEncode(v)
	}
	return v, nil
}

// resolveURLEncode implements curl's five --data-urlencode argument forms:
//
//	content        → urlencode the whole string
//	=content       → urlencode content, emit without a name
//	name=content   → emit name=urlencode(content)
//	@file          → urlencode the file's contents
//	name@file      → emit name=urlencode(file contents)
func resolveURLEncode(v string) (string, error) {
	if strings.HasPrefix(v, "=") {
		return url.QueryEscape(v[1:]), nil
	}
	if strings.HasPrefix(v, "@") {
		content, err := readDataFile(v[1:])
		if err != nil {
			return "", err
		}
		return url.QueryEscape(content), nil
	}
	// name=content wins over name@file when both separators are present, as
	// curl scans for '=' first.
	if name, content, ok := strings.Cut(v, "="); ok && !strings.Contains(name, "@") {
		return name + "=" + url.QueryEscape(content), nil
	}
	if name, file, ok := strings.Cut(v, "@"); ok {
		content, err := readDataFile(file)
		if err != nil {
			return "", err
		}
		return name + "=" + url.QueryEscape(content), nil
	}
	return url.QueryEscape(v), nil
}

// readDataFile reads a body-data file referenced with '@'. A missing file is a
// hard error: the body is the whole point of the flag, and silently sending an
// empty or literal-path body would misrepresent the request.
func readDataFile(path string) (string, error) {
	if path == "-" {
		return "", fmt.Errorf("reading body data from stdin (@-) is not supported here; inline the data instead")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read data file %q: %w", path, err)
	}
	return string(b), nil
}

// formPart is one -F/--form field.
type formPart struct {
	name        string
	value       string
	filename    string // non-empty for file parts
	contentType string
}

// parseFormPart parses curl's -F syntax: "name=value", "name=@path" (upload),
// "name=<path" (file contents as the value), each optionally suffixed with
// ";type=<mime>" and ";filename=<name>".
//
// A referenced file that doesn't exist is NOT fatal. The point of parsing a
// curl command here is to reconstruct the request's *shape* so it can be
// replayed or fuzzed, usually on a different machine from the one the command
// was copied off; a placeholder body preserves that shape, where an error
// would throw the whole request away.
func parseFormPart(field string, literal bool) (formPart, bool) {
	name, rest, ok := strings.Cut(field, "=")
	if !ok {
		return formPart{}, false
	}
	p := formPart{name: name}

	// Split trailing ";key=value" attributes off the value.
	value := rest
attrs:
	for {
		idx := strings.LastIndex(value, ";")
		if idx < 0 {
			break
		}
		key, val, hasVal := strings.Cut(strings.TrimSpace(value[idx+1:]), "=")
		if !hasVal {
			break
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "type":
			p.contentType = strings.TrimSpace(val)
		case "filename":
			p.filename = strings.TrimSpace(val)
		default:
			// Not an attribute we know — it belongs to the value.
			break attrs
		}
		value = value[:idx]
	}

	switch {
	case literal:
		// --form-string: the value is never interpreted.
		p.value = value

	case strings.HasPrefix(value, "@"), strings.HasPrefix(value, "<"):
		path := value[1:]
		upload := strings.HasPrefix(value, "@")
		content, err := os.ReadFile(path)
		if err == nil {
			p.value = string(content)
		} else {
			p.value = fmt.Sprintf("<contents of %s>", filepath.Base(path))
		}
		if upload && p.filename == "" {
			p.filename = filepath.Base(path)
		}

	default:
		p.value = value
	}
	return p, true
}

// BuildMultipartBody assembles a real multipart/form-data body and returns it
// with the matching Content-Type (boundary included). The boundary is derived
// from the field contents so a given command always produces identical bytes —
// which keeps replays reproducible and tests stable.
func BuildMultipartBody(fields, literalFields []string) (body, contentType string) {
	var parts []formPart
	for _, f := range fields {
		if p, ok := parseFormPart(f, false); ok {
			parts = append(parts, p)
		}
	}
	for _, f := range literalFields {
		if p, ok := parseFormPart(f, true); ok {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return "", ""
	}

	mparts := make([]multipartform.Part, len(parts))
	for i, p := range parts {
		mparts[i] = multipartform.Part{Name: p.name, FileName: p.filename, ContentType: p.contentType, Value: p.value}
	}
	body, contentType, err := multipartform.Build(mparts, multipartBoundary(parts))
	if err != nil {
		return "", ""
	}
	return body, contentType
}

// multipartBoundary derives a stable boundary from the parts so identical
// input yields identical bytes.
func multipartBoundary(parts []formPart) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00", p.name, p.value, p.filename, p.contentType)
	}
	return "vigolium" + hex.EncodeToString(h.Sum(nil))[:32]
}

// GuessContentType picks the Content-Type for a body sent with -d when the
// command didn't set one. curl always uses application/x-www-form-urlencoded,
// but a JSON body with that header is a request no server was ever meant to
// receive — and pasted commands routinely omit the header. So: JSON when the
// body actually parses as a JSON object or array, curl's default otherwise.
func GuessContentType(body string) string {
	if looksLikeJSON(body) {
		return "application/json"
	}
	return "application/x-www-form-urlencoded"
}

// looksLikeJSON reports whether body is a JSON object or array. It checks the
// delimiters and balance rather than fully unmarshalling, so a body with a
// deliberately malformed value (the common case when the command came from a
// security test) is still recognized.
func looksLikeJSON(body string) bool {
	t := strings.TrimSpace(body)
	if len(t) < 2 {
		return false
	}
	first, last := t[0], t[len(t)-1]
	return (first == '{' && last == '}') || (first == '[' && last == ']')
}
