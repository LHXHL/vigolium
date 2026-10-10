package database

import (
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg/pathshape"
)

var (
	reTokenLong = regexp.MustCompile(`^[A-Za-z0-9_-]{20,}$`)
	reVersion   = regexp.MustCompile(`(?i)^v\d+$`)
)

// templateSegmentIsDynamic reports whether PathToTemplate wildcards seg. It is
// pathshape's classification (ints, UUIDs, hex ≥8, dates, timestamps, emails,
// JWTs, base64 ≥16) plus this package's legacy long-token rule (≥20 chars of
// [A-Za-z0-9_-]), kept so the related-record LIKE patterns never get narrower
// than they were. Version segments (v1, v2, v10) are never dynamic.
func templateSegmentIsDynamic(seg string) bool {
	if seg == "" || reVersion.MatchString(seg) {
		return false
	}
	return pathshape.Kind(seg).Dynamic() || reTokenLong.MatchString(seg)
}

// HasDynamicSegment returns true if the path contains at least one dynamic
// segment — one PathToTemplate would replace with "*".
// Version-like segments (v1, v2, v10) are not considered dynamic.
func HasDynamicSegment(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if templateSegmentIsDynamic(seg) {
			return true
		}
	}
	return false
}

// PathToTemplate normalizes a URL path for related-record lookup by replacing
// dynamic path segments (IDs, UUIDs, tokens) with a wildcard "*".
// Static segments and version segments (v1, v2, v10) are preserved.
// The resulting template uses "*" which callers can replace with "%" for SQL LIKE.
//
// It is a thin wrapper over pkg/httpmsg/pathshape (whose "{kind}" placeholders
// all become "*") plus the legacy long-token rule:
//   - pathshape kinds: integers, UUIDs, all-hex ≥ 8 chars, ISO dates and
//     timestamps, emails, JWTs, base64 ≥ 16 chars
//   - Long alphanumeric ≥ 20 chars (token-like): `^[A-Za-z0-9_-]{20,}$`
//
// Version-like segments (v1, v2, v10) are always kept as-is.
func PathToTemplate(path string) string {
	if path == "" {
		return path
	}

	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if templateSegmentIsDynamic(seg) {
			segments[i] = "*"
		}
	}
	return strings.Join(segments, "/")
}
