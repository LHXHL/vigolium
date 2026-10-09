// Package pathshape reduces a URL path to its structural template, so
// /users/42/orders/550e8400-… and /users/7/orders/9b2f… are recognised as the
// same endpoint (/users/{int}/orders/{uuid}) while /users/me, /about-us and
// /blog/my-post stay distinct.
//
// It is the one shared path normalizer: param-shape coalescing, related-record
// lookup (database.PathToTemplate), spitolas seed sampling, harvester and
// sitemap sampling, and endpoint grouping all build on it. It is a leaf package
// (stdlib plus pkg/mutation) so any of those can import it without a cycle.
//
// The rules are deliberately conservative — a segment collapses only when it is
// a high-confidence per-record value:
//   - integers (including "0"/"1", which mutation.Classify calls Boolean),
//     UUIDs, all-hex runs of ≥8 chars, ISO dates and timestamps, emails, JWTs,
//     and base64 blobs of ≥16 chars;
//   - version segments (v1, v2, v10) always stay literal;
//   - slugs, enum-like words and anything unclassified never collapse, so
//     /about-us and /blog/my-post keep their own shape.
package pathshape

import (
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/mutation"
)

// SegKind is the classification of one path segment. Its string value is the
// placeholder name used in templates ("{int}", "{uuid}", …).
type SegKind string

const (
	Literal SegKind = "literal" // kept verbatim in the template
	Int     SegKind = "int"     // 42, 0, 1
	UUID    SegKind = "uuid"    // 550e8400-e29b-41d4-a716-446655440000
	Hex     SegKind = "hex"     // e3b0c442…, ≥8 hex chars
	Date    SegKind = "date"    // 2024-01-02
	TS      SegKind = "ts"      // 2024-01-02T10:30:00Z
	B64     SegKind = "b64"     // base64 blob, ≥16 chars
	Email   SegKind = "email"   // user@example.com
	JWT     SegKind = "jwt"     // eyJhbGciOi….….…
)

// Dynamic reports whether a segment of this kind is normalized to a
// placeholder (anything but Literal).
func (k SegKind) Dynamic() bool { return k != Literal && k != "" }

// Placeholder returns the template token for a dynamic kind ("{int}"), or ""
// for Literal.
func (k SegKind) Placeholder() string {
	if !k.Dynamic() {
		return ""
	}
	return "{" + string(k) + "}"
}

const (
	minHexLen = 8
	minB64Len = 16
)

var (
	reVersion = regexp.MustCompile(`(?i)^v\d+$`)
	reDigits  = regexp.MustCompile(`^\d+$`)
	reHex     = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// Kind classifies a single path segment (no slashes).
func Kind(seg string) SegKind {
	if seg == "" || reVersion.MatchString(seg) {
		return Literal
	}
	// Pure digits are an int regardless of length; mutation.Classify would call
	// long ones a phone or credit-card number.
	if reDigits.MatchString(seg) {
		return Int
	}
	// Short hex runs (8–15 chars) and odd-length ones fall outside
	// mutation.Classify's hex rule, and upper-case ones can read as base64.
	if len(seg) >= minHexLen && reHex.MatchString(seg) {
		return Hex
	}
	switch mutation.Classify(seg, nil) {
	case mutation.TypeBoolean:
		// Classify may report "0"/"1" as Boolean; in a path they are ids.
		if seg == "0" || seg == "1" {
			return Int
		}
	case mutation.TypeInteger, mutation.TypeSequentialID:
		return Int
	case mutation.TypeUUID:
		return UUID
	case mutation.TypeHexEncoded:
		return Hex
	case mutation.TypeDate:
		return Date
	case mutation.TypeTimestamp:
		return TS
	case mutation.TypeEmail:
		return Email
	case mutation.TypeJWT:
		return JWT
	case mutation.TypeBase64:
		if len(seg) >= minB64Len {
			return B64
		}
	}
	// Slug, enum, unknown and every other type stay literal.
	return Literal
}

// Segments returns the non-empty segments of path, in order. Shape's kinds
// slice is aligned with it, so callers can zip a kind with its concrete value.
func Segments(path string) []string {
	parts := strings.Split(path, "/")
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Shape returns the structural template of path, e.g.
// "/users/{int}/orders/{uuid}", plus the kind of every non-empty segment (aligned
// with Segments(path)). Slashes, including leading, trailing and doubled ones,
// are preserved, so a path with no dynamic segment returns itself unchanged.
func Shape(path string) (template string, kinds []SegKind) {
	if path == "" {
		return "", nil
	}
	parts := strings.Split(path, "/")
	changed := false
	for i, seg := range parts {
		if seg == "" {
			continue
		}
		k := Kind(seg)
		kinds = append(kinds, k)
		if k.Dynamic() {
			parts[i] = k.Placeholder()
			changed = true
		}
	}
	if !changed {
		return path, kinds
	}
	return strings.Join(parts, "/"), kinds
}
