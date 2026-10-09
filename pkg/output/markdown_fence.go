package output

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/utils/textutil"
)

// DefaultMarkdownMaxBodyBytes is the shared cap applied to each request and
// response embedded in a Markdown report when the caller sets no limit.
const DefaultMarkdownMaxBodyBytes = 4096

// MarkdownFence returns the opening and closing lines of a fenced code block
// that safely encloses body. The fence is a run of backticks one longer than
// the longest backtick run inside body (minimum three), so a captured response
// that itself contains ``` — a README, a Markdown API, an LLM reply — cannot
// close the block early and spill raw HTTP into the surrounding document.
func MarkdownFence(body, lang string) (open, close string) {
	n := longestRun(body, '`') + 1
	if n < 3 {
		n = 3
	}
	fence := strings.Repeat("`", n)
	return fence + lang, fence
}

// MarkdownCodeSpan renders s as an inline code span using the same rule as
// MarkdownFence: the delimiter is one backtick longer than the longest run
// inside s, padded with a space when s starts or ends with a backtick
// (CommonMark strips exactly one such space on each side). Newlines are
// folded to spaces since a code span cannot hold a line break.
func MarkdownCodeSpan(s string) string {
	s = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ").Replace(s)
	delim := strings.Repeat("`", longestRun(s, '`')+1)
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		return delim + " " + s + " " + delim
	}
	return delim + s + delim
}

// longestRun returns the length of the longest consecutive run of c in s.
func longestRun(s string, c byte) int {
	longest, cur := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			cur++
			if cur > longest {
				longest = cur
			}
			continue
		}
		cur = 0
	}
	return longest
}

// truncateMarkdownHTTP caps one raw HTTP message for a Markdown report. It
// returns the (possibly shortened) text and, when it cut, a note naming the
// kept and total sizes and the command that prints the whole message. The cut
// never splits a UTF-8 sequence. maxBytes <= 0 disables the cap.
func truncateMarkdownHTTP(raw string, maxBytes int, fullCmd string) (body, note string) {
	if maxBytes <= 0 || len(raw) <= maxBytes {
		return raw, ""
	}
	kept := textutil.TruncateUTF8(raw, maxBytes)
	note = fmt.Sprintf("… [truncated, %d of %d bytes", len(kept), len(raw))
	if fullCmd != "" {
		note += "; full: " + fullCmd
	}
	return kept, note + "]"
}
