package modkit

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
)

// The expressions collapseDynamicRuns replaced. They live here, in the test,
// as the specification the scan is held to: the implementation no longer runs
// them, so this is the only thing keeping the two definitions in agreement.
var (
	refHexLong = regexp.MustCompile(`[0-9a-fA-F]{12,}`)
	refDigits  = regexp.MustCompile(`[0-9]{4,}`)
)

// refCollapse is the original two-pass regexp normalization.
func refCollapse(s string) string {
	s = refHexLong.ReplaceAllString(s, " ")
	s = refDigits.ReplaceAllString(s, " ")
	return s
}

// collapseToString runs the scan and concatenates what it emits, so a test can
// compare against refCollapse directly.
func collapseToString(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	collapseDynamicRuns(s, func(chunk string) { b.WriteString(chunk) })
	return b.String()
}

// refNormalizedBodyHash is NormalizedBodyHash as it was before the rewrite. It
// pins the stored-hash contract: response_norm_hash values already in users'
// databases were produced by this, so a change here silently splits every
// existing dedup group.
func refNormalizedBodyHash(body string, reflects ...string) string {
	if strings.TrimSpace(body) == "" {
		return ""
	}
	s := strings.ToLower(body)
	for _, ref := range reflects {
		if len(ref) >= 3 {
			s = strings.ReplaceAll(s, strings.ToLower(ref), " ")
		}
	}
	s = refCollapse(s)
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// refNormalizeForRatio is NormalizeForRatio as it was before the rewrite.
func refNormalizeForRatio(body, reflect string) string {
	s := strings.ToLower(capForRatio(body))
	if len(reflect) >= 3 {
		s = strings.ReplaceAll(s, strings.ToLower(reflect), " ")
	}
	return refCollapse(s)
}

var collapseCases = []string{
	"",
	" ",
	"abc",
	"<title>Hi</title>",
	"deadbeefdeadbeef",                 // 16 hex: collapses whole
	"deadbeefdead",                     // exactly 12: collapses
	"deadbeefdea",                      // 11: survives
	"1234",                             // exactly 4 digits: collapses
	"123",                              // 3 digits: survives
	"12345678901234567890",             // 20 digits, also 20 hex: hex wins
	"a9f3c2b18e7d4051",                 // id-shaped
	"abcdefabcdef1234",                 // 16 hex run containing a digit run
	"0000abcdef",                       // 10 hex, digit run of 4 inside
	"zz1234zz",                         // digit run bounded by non-hex
	"ff1234ff",                         // digit run bounded by hex letters
	"x0000x1111x",                      // two separate digit runs
	"abc 123456789012 def",             // hex run bounded by spaces
	"\x00\xff\xfe binary 123456789012", // non-UTF-8 bytes around a run
	"héllo ÄÖÜ 9999 ﬀ İstanbul",        // multibyte either side of a digit run
	"K kelvin ſ long-s",                // runes whose lowering leaves ASCII
	"０１２３４ fullwidth digits",           // fullwidth digits are not [0-9]
	"/path?x=1",
	"http://example.test/path",
	strings.Repeat("a", 4096),
	strings.Repeat("0", 4096), // spans many staging-buffer flushes
	strings.Repeat("ab12", 2048),
}

func TestCollapseDynamicRunsMatchesRegexp(t *testing.T) {
	for _, in := range collapseCases {
		// Lowercased first, as every caller does: the scan is only equivalent on
		// input that holds no ASCII uppercase.
		s := strings.ToLower(in)
		if got, want := collapseToString(s), refCollapse(s); got != want {
			t.Errorf("collapseDynamicRuns(%q) = %q, regexp pair = %q", s, got, want)
		}
	}
}

func TestNormalizedBodyHashUnchanged(t *testing.T) {
	reflects := [][]string{
		nil,
		{"/path"},
		{"/path", "http://example.test/path"},
		{"http://example.test/path", "/path"}, // reversed: order is load-bearing
		{"ab"},                                // under the 3-byte floor, ignored
	}
	for _, body := range collapseCases {
		for _, refs := range reflects {
			got := NormalizedBodyHash(body, refs...)
			want := refNormalizedBodyHash(body, refs...)
			if got != want {
				t.Errorf("NormalizedBodyHash(%q, %q) = %s, was %s", body, refs, got, want)
			}
		}
	}
}

func TestNormalizeForRatioUnchanged(t *testing.T) {
	for _, body := range collapseCases {
		for _, reflect := range []string{"", "/path", "http://example.test/path"} {
			got := NormalizeForRatio(body, reflect)
			want := refNormalizeForRatio(body, reflect)
			if got != want {
				t.Errorf("NormalizeForRatio(%q, %q) = %q, was %q", body, reflect, got, want)
			}
		}
	}
}

func FuzzCollapseDynamicRunsMatchesRegexp(f *testing.F) {
	for _, c := range collapseCases {
		f.Add(c, "/path", "http://example.test/path")
	}
	f.Fuzz(func(t *testing.T, body, r1, r2 string) {
		s := strings.ToLower(body)
		if got, want := collapseToString(s), refCollapse(s); got != want {
			t.Fatalf("collapse mismatch on %q:\n got %q\nwant %q", s, got, want)
		}
		if got, want := NormalizedBodyHash(body, r1, r2), refNormalizedBodyHash(body, r1, r2); got != want {
			t.Fatalf("hash mismatch on body=%q r1=%q r2=%q:\n got %s\nwant %s", body, r1, r2, got, want)
		}
		if got, want := NormalizeForRatio(body, r1), refNormalizeForRatio(body, r1); got != want {
			t.Fatalf("ratio mismatch on body=%q reflect=%q:\n got %q\nwant %q", body, r1, got, want)
		}
	})
}
