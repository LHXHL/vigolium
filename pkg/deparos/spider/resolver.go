package spider

import (
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
)

// URLResolver resolves relative URLs against a base URL and normalizes them.
type URLResolver struct {
	// No fields needed - stateless resolver
}

// NewURLResolver creates a new URL resolver.
func NewURLResolver() *URLResolver {
	return &URLResolver{}
}

// urlGarbageChars are characters to remove from a URL during sanitization.
// These appear from JavaScript escapes (\/, \") that get URL-encoded.
//
//	\\ backslash from JS escapes   " quote from JS strings
//	'  single quote                ` backtick from template literals
//	\t tab, \n newline, \r carriage return
//
// A string so stripURLGarbage can hand it to strings.ContainsAny for its
// fast path; isURLGarbageChar indexes the same source of truth.
const urlGarbageChars = "\\\"'`\t\n\r"

// isURLGarbageChar checks if byte is a garbage character for URL resolution.
func isURLGarbageChar(c byte) bool {
	for i := 0; i < len(urlGarbageChars); i++ {
		if c == urlGarbageChars[i] {
			return true
		}
	}
	return false
}

// decodeJSEscapes interprets JavaScript escape sequences in a string.
// Handles:
//   - \uXXXX (Unicode escapes, 4 hex digits)
//   - \xXX (Hex escapes, 2 hex digits)
//
// Returns the decoded string with escape sequences converted to their characters.
func decodeJSEscapes(s string) string {
	// Fast path: no backslash means no escapes
	if !strings.Contains(s, "\\") {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))

	i := 0
	for i < len(s) {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}

		// Check what follows the backslash
		next := s[i+1]

		// \uXXXX - Unicode escape (4 hex digits)
		if next == 'u' && i+5 < len(s) {
			hex := s[i+2 : i+6]
			if isHexString(hex) {
				if r, err := strconv.ParseInt(hex, 16, 32); err == nil {
					b.WriteRune(rune(r))
					i += 6
					continue
				}
			}
		}

		// \xXX - Hex escape (2 hex digits)
		if next == 'x' && i+3 < len(s) {
			hex := s[i+2 : i+4]
			if isHexString(hex) {
				if r, err := strconv.ParseInt(hex, 16, 32); err == nil {
					b.WriteRune(rune(r))
					i += 4
					continue
				}
			}
		}

		// Not a recognized escape, write the backslash and continue
		b.WriteByte(s[i])
		i++
	}

	return b.String()
}

// isHexString checks if all characters in s are valid hexadecimal digits.
func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// sanitizePathForResolution cleans a raw URL before resolution.
// Decodes URL-encoded characters and removes garbage (backslashes, quotes, etc).
func (r *URLResolver) sanitizePathForResolution(rawURL string) string {
	// Skip if clearly an absolute URL with scheme - clean path component only
	if strings.Contains(rawURL, "://") {
		u, err := url.Parse(rawURL)
		if err != nil {
			return rawURL
		}
		// Clean the path component
		u.Path = r.cleanPathForResolution(u.Path)
		if u.Path == "" {
			u.Path = "/"
		}
		return u.String()
	}

	// Skip protocol-relative URLs (//host/path) - don't collapse leading //
	if strings.HasPrefix(rawURL, "//") {
		return rawURL
	}

	// Relative reference. Split the path from the query/fragment and clean each
	// with the rules that suit it, instead of running the path rules over the
	// whole string.
	//
	// The absolute branch above always did this — url.Parse separated the
	// components for it — so only relative references were affected, which is the
	// overwhelming majority of what an href or a mined string looks like. Two of
	// the path rules actively rewrite query semantics:
	//
	//   - PathUnescape turns %26 into a literal '&', so /item?label=a%26b resolved
	//     to /item?label=a&b: one parameter carrying "a&b" silently became two
	//     parameters. The same applies to %3D and %2B.
	//   - The "//" -> "/" collapse destroys an embedded absolute URL, so
	//     ?next=https://host/x became ?next=https:/host/x.
	//
	// Both produce a URL that parses fine and requests something the application
	// never offered, which is worse than dropping it.
	path, suffix := splitPathFromQuery(rawURL)
	return r.cleanPathForResolution(path) + cleanQuerySourceNoise(suffix)
}

// splitPathFromQuery divides a relative reference at the first '?' or '#',
// returning the path and the remainder (including the delimiter, or "" if there
// is none).
func splitPathFromQuery(rawURL string) (path, suffix string) {
	if i := strings.IndexAny(rawURL, "?#"); i != -1 {
		return rawURL[:i], rawURL[i:]
	}
	return rawURL, ""
}

// cleanQuerySourceNoise strips the noise a query picks up from the SOURCE SYNTAX
// it was mined out of — JS string escapes, stray quotes, embedded newlines — and
// nothing else.
//
// Deliberately narrower than cleanPathForResolution: percent-decoding and slash
// collapsing are meaningful transformations of a path but corruptions of a
// query, where the encoding is what separates one parameter value from the next.
func cleanQuerySourceNoise(suffix string) string {
	return stripURLGarbage(decodeJSEscapes(suffix))
}

// stripURLGarbage removes the bytes that are never legal in a URL and only ever
// arrive from the source syntax a URL was mined out of. Shared by the path and
// query cleaners so the two cannot drift on what counts as garbage.
//
// Returns s unchanged when there is nothing to strip, which is the overwhelming
// majority of calls — this runs per discovered link, so the scan-and-return is
// worth more than the builder it avoids. Same fast-path idiom as decodeJSEscapes.
func stripURLGarbage(s string) string {
	if !strings.ContainsAny(s, urlGarbageChars) {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if !isURLGarbageChar(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// cleanPathForResolution decodes and removes garbage from a path string.
func (r *URLResolver) cleanPathForResolution(p string) string {
	// Decode URL-encoded characters (up to 3 levels for triple-encoding)
	decoded := p
	for i := 0; i < 3; i++ {
		newDecoded, err := url.PathUnescape(decoded)
		if err != nil || newDecoded == decoded {
			break
		}
		decoded = newDecoded
	}

	// Decode JavaScript escape sequences (\uXXXX, \xXX)
	decoded = decodeJSEscapes(decoded)

	// Remove garbage characters
	result := stripURLGarbage(decoded)

	// Collapse double slashes
	for strings.Contains(result, "//") {
		result = strings.ReplaceAll(result, "//", "/")
	}

	// Sanitize path segments (remove unbalanced brackets)
	// Uses trimUnbalancedBrackets and hasAlphanumeric from path_normalize.go
	result = sanitizePathSegments(result)

	return result
}

// sanitizePathSegments cleans path segments by removing unbalanced brackets.
// Segments that become empty or have no alphanumeric content are skipped,
// except for "." and ".." which are preserved for path resolution.
//
// Examples:
//   - "/v2/]/v2/welcome" → "/v2/v2/welcome"
//   - "/v2/plain]/type" → "/v2/plain/type"
//   - "/api/[/test" → "/api/test"
//   - "../admin" → "../admin" (preserved for resolution)
func sanitizePathSegments(p string) string {
	if p == "" || p == "/" {
		return p
	}

	segments := strings.Split(p, "/")
	result := make([]string, 0, len(segments))
	hasValidSegment := false

	for _, seg := range segments {
		if seg == "" {
			result = append(result, "")
			continue
		}

		// Preserve . and .. for path resolution
		if seg == "." || seg == ".." {
			result = append(result, seg)
			hasValidSegment = true
			continue
		}

		// Trim unbalanced brackets from edges
		// Uses trimUnbalancedBrackets from path_normalize.go
		cleaned := trimUnbalancedBrackets(seg)

		// Skip if no alphanumeric content
		// Uses hasAlphanumeric from path_normalize.go
		if cleaned == "" || !hasAlphanumeric(cleaned) {
			continue
		}

		result = append(result, cleaned)
		hasValidSegment = true
	}

	// No valid segments found
	if !hasValidSegment {
		return ""
	}

	return strings.Join(result, "/")
}

// Resolve resolves a relative URL against a base URL.
// Handles:
// - Absolute URLs (returned as-is after parsing)
// - Protocol-relative URLs (//example.com/path)
// - Absolute paths (/path)
// - Relative paths (../path, path)
func (r *URLResolver) Resolve(base *url.URL, relativeURL string) (*url.URL, error) {
	if base == nil {
		return nil, fmt.Errorf("base URL is nil")
	}

	if relativeURL == "" {
		return nil, fmt.Errorf("relative URL is empty")
	}

	// Trim whitespace
	relativeURL = strings.TrimSpace(relativeURL)

	// Sanitize before parsing - removes backslashes, quotes, and other garbage
	// that appear from JavaScript escapes (e.g., \/trading\/ or \"/api/\")
	relativeURL = r.sanitizePathForResolution(relativeURL)
	if relativeURL == "" {
		return nil, fmt.Errorf("empty URL after sanitization")
	}

	// Parse the relative URL
	ref, err := url.Parse(relativeURL)
	if err != nil {
		return nil, fmt.Errorf("parse relative URL: %w", err)
	}

	// Resolve against base
	resolved := base.ResolveReference(ref)

	// Normalize the result
	normalized := r.normalize(resolved)

	return normalized, nil
}

// Normalize canonicalizes a URL preserving query params.
// Returns full URL string with query params for HTTP requests.
func (r *URLResolver) Normalize(u *url.URL) string {
	if u == nil {
		return ""
	}

	canonical := &url.URL{
		Scheme:   strings.ToLower(u.Scheme),
		Host:     strings.ToLower(u.Host),
		Path:     r.normalizePath(u.Path),
		RawQuery: u.RawQuery, // Preserve query params for HTTP requests
		// Fragment intentionally omitted - not useful for discovery
	}

	return canonical.String()
}

// normalize returns a normalized copy of the URL.
//
// Known limitation, deliberately left as-is: the copy is built from the decoded
// Path and carries no RawPath, so a percent-encoded path separator (/a%2Fb) is
// emitted as a real one (/a/b). That is not an oversight here — the path is
// already percent-decoded upstream by cleanPathForResolution, which is what makes
// the recovery of JS-escaped strings like "\/trading\/" work at all. Preserving
// RawPath at this point would have nothing left to preserve.
//
// Fixing it properly means not decoding path escapes during sanitization, which
// changes what this extractor is for. The query is a different matter and IS
// preserved verbatim below: there, encoding is what keeps one parameter value
// from becoming two. See cleanQuerySourceNoise.
func (r *URLResolver) normalize(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}

	return &url.URL{
		Scheme:   strings.ToLower(u.Scheme),
		Host:     strings.ToLower(u.Host),
		Path:     r.normalizePath(u.Path),
		RawQuery: u.RawQuery, // Preserve query params for HTTP requests
		// Fragment intentionally omitted - not useful for discovery
	}
}

// Bracket characters that may be unbalanced in path segments.
var unbalancedBracketChars = [...]byte{
	'[', ']', '{', '}', '<', '>',
}

// isUnbalancedBracketChar checks if byte is a bracket character.
func isUnbalancedBracketChar(c byte) bool {
	for _, bc := range unbalancedBracketChars {
		if c == bc {
			return true
		}
	}
	return false
}

// trimUnbalancedBrackets removes unbalanced bracket chars from segment edges.
// Only trims if the segment has unbalanced brackets overall.
// If balanced (e.g., [id], {param}), returns unchanged.
//
// Examples:
//   - "plain]" → "plain" (unbalanced, trim ])
//   - "]" → "" (unbalanced, becomes empty)
//   - "[invalid" → "invalid" (unbalanced, trim [)
//   - "]]test[[" → "test" (unbalanced, trim all)
//   - "{foo" → "foo" (unbalanced, trim {)
//   - "[id]" → "[id]" (balanced, unchanged)
//   - "{param}" → "{param}" (balanced, unchanged)
func trimUnbalancedBrackets(seg string) string {
	// Check if brackets are balanced - if so, return unchanged
	if hasBalancedBrackets(seg) {
		return seg
	}

	// Trim unbalanced brackets from edges recursively
	for len(seg) > 0 {
		changed := false

		// Trim from start if it's a bracket
		if len(seg) > 0 && isUnbalancedBracketChar(seg[0]) {
			seg = seg[1:]
			changed = true
		}

		// Trim from end if it's a bracket
		if len(seg) > 0 && isUnbalancedBracketChar(seg[len(seg)-1]) {
			seg = seg[:len(seg)-1]
			changed = true
		}

		if !changed {
			break
		}
	}

	return seg
}

// hasBalancedBrackets checks if segment has balanced brackets.
func hasBalancedBrackets(seg string) bool {
	openSquare := strings.Count(seg, "[")
	closeSquare := strings.Count(seg, "]")
	openCurly := strings.Count(seg, "{")
	closeCurly := strings.Count(seg, "}")
	openAngle := strings.Count(seg, "<")
	closeAngle := strings.Count(seg, ">")

	if openSquare != closeSquare || openCurly != closeCurly || openAngle != closeAngle {
		return false
	}

	// Also check proper ordering (opening before closing)
	if openSquare > 0 && strings.Index(seg, "[") > strings.LastIndex(seg, "]") {
		return false
	}
	if openCurly > 0 && strings.Index(seg, "{") > strings.LastIndex(seg, "}") {
		return false
	}
	if openAngle > 0 && strings.Index(seg, "<") > strings.LastIndex(seg, ">") {
		return false
	}

	return true
}

// hasAlphanumeric checks if string contains at least one a-zA-Z0-9.
func hasAlphanumeric(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			return true
		}
	}
	return false
}

// normalizePath normalizes a URL path
//
// Normalization:
//   - Collapse multiple slashes: //api → /api
//   - Resolve . and .. segments
//   - Preserve trailing slash distinction
//
// Matches storage/canonicalize.go normalizePath()
func (r *URLResolver) normalizePath(p string) string {
	if p == "" {
		return "/"
	}

	// Guard: paths should never contain "://" - indicates upstream bug
	// Parse and extract just the path to avoid corruption
	if strings.Contains(p, "://") {
		if u, err := url.Parse(p); err == nil && u.Path != "" {
			p = u.Path
		}
	}

	// Track if path had trailing slash
	hasTrailingSlash := strings.HasSuffix(p, "/") && p != "/"

	// Use path.Clean to collapse // and resolve . and ..
	cleaned := path.Clean(p)

	// path.Clean removes trailing slash, restore if needed
	if hasTrailingSlash && !strings.HasSuffix(cleaned, "/") {
		cleaned += "/"
	}

	// Ensure leading slash
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}

	return cleaned
}
