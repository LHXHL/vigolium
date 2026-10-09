// Package textutil holds small, dependency-free string helpers that every
// renderer needs and none should reimplement: truncation that never splits a
// UTF-8 sequence.
//
// Byte slicing (s[:n]) cuts wherever n lands, which in a multibyte response
// body or a CJK title leaves half a rune at the end. JSON encoders then
// substitute U+FFFD, SARIF validators reject the file, and terminals print
// garbage. Every "cap this string" site should go through here instead.
package textutil

import (
	"strings"
	"unicode/utf8"
)

// CutIndex returns the largest index i <= maxBytes such that s[:i] does not
// end in the middle of a multibyte UTF-8 sequence that starts before i. It
// returns len(s) when s already fits and 0 for a non-positive maxBytes.
//
// It only moves the cut; it never rewrites bytes, so callers holding binary or
// non-UTF-8 data (an HTTP body) keep it byte-exact up to the cut.
func CutIndex[T ~string | ~[]byte](s T, maxBytes int) int {
	if maxBytes <= 0 {
		return 0
	}
	if len(s) <= maxBytes {
		return len(s)
	}
	cut := maxBytes
	// Back off over continuation bytes to the start of the rune straddling the
	// cut. A valid sequence is at most UTFMax bytes, so never look further back
	// than that — invalid data then still cuts close to maxBytes.
	for back := 0; cut > 0 && back < utf8.UTFMax && !utf8.RuneStart(s[cut]); back++ {
		cut--
	}
	if !utf8.RuneStart(s[cut]) {
		// No rune start within UTFMax bytes: the data is not UTF-8 here, so
		// cutting at maxBytes splits nothing meaningful.
		return maxBytes
	}
	return cut
}

// TruncateUTF8 returns the longest prefix of s that is at most maxBytes long
// and does not split a UTF-8 sequence. The result is always valid UTF-8:
// invalid bytes inside the kept prefix are replaced with U+FFFD, dropping
// trailing runes as needed so the length bound still holds. A string that fits
// and is already valid is returned unchanged (no allocation).
func TruncateUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	prefix := s[:CutIndex(s, maxBytes)]
	if utf8.ValidString(prefix) {
		return prefix
	}
	return sanitizePrefix(prefix, maxBytes)
}

// TruncateRunes returns at most maxRunes runes of s, as valid UTF-8 (invalid
// bytes count as one rune each and are replaced with U+FFFD). Use it for
// character budgets — a chat-message limit, a title cap — where the bound is
// in characters rather than bytes.
func TruncateRunes(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	n := 0
	for i := range s {
		if n == maxRunes {
			return validOrSanitized(s[:i])
		}
		n++
	}
	return validOrSanitized(s)
}

// TruncateUTF8Ellipsis caps s at maxBytes bytes in total, replacing the tail
// with ellipsis when it had to cut. When maxBytes cannot hold the ellipsis the
// plain truncation is returned, so the bound is never exceeded.
func TruncateUTF8Ellipsis(s string, maxBytes int, ellipsis string) string {
	if len(s) <= maxBytes && utf8.ValidString(s) {
		return s
	}
	if len(s) <= maxBytes {
		return TruncateUTF8(s, maxBytes)
	}
	if maxBytes <= len(ellipsis) {
		return TruncateUTF8(s, maxBytes)
	}
	return TruncateUTF8(s, maxBytes-len(ellipsis)) + ellipsis
}

// TruncateRunesEllipsis caps s at maxRunes runes in total, replacing the tail
// with ellipsis when it had to cut. When maxRunes cannot hold the ellipsis the
// plain truncation is returned.
func TruncateRunesEllipsis(s string, maxRunes int, ellipsis string) string {
	if utf8.RuneCountInString(s) <= maxRunes {
		return validOrSanitized(s)
	}
	el := utf8.RuneCountInString(ellipsis)
	if maxRunes <= el {
		return TruncateRunes(s, maxRunes)
	}
	return TruncateRunes(s, maxRunes-el) + ellipsis
}

func validOrSanitized(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "\uFFFD")
}

// sanitizePrefix rebuilds s with each invalid byte replaced by U+FFFD, stopping
// before the output would exceed maxBytes. U+FFFD is three bytes, so a
// replacement can push later runes past the bound; those are dropped.
func sanitizePrefix(s string, maxBytes int) string {
	var b strings.Builder
	b.Grow(min(len(s)+8, maxBytes))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		piece := s[i : i+size]
		if r == utf8.RuneError && size == 1 {
			piece = "\uFFFD"
		}
		if b.Len()+len(piece) > maxBytes {
			break
		}
		b.WriteString(piece)
		i += size
	}
	return b.String()
}
