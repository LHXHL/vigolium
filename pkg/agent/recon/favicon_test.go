package recon

import (
	"strings"
	"testing"
)

// The vectors are gimorra's (packages/recon/src/favicon-hash.test.ts), generated
// with Python's mmh3 reference and base64.encodebytes — the form Shodan and FOFA
// index. A drift here makes every hash this pass stores pivot against nothing.
func TestFaviconHashMatchesTheReference(t *testing.T) {
	fixture := make([]byte, 0, 3*256+8+57)
	for r := 0; r < 3; r++ {
		for i := 0; i < 256; i++ {
			fixture = append(fixture, byte(i))
		}
	}
	fixture = append(fixture, 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)
	fixture = append(fixture, []byte(strings.Repeat("x", 57))...)

	info := HashFavicon("https://h.example/favicon.ico", fixture)
	if info.MMH3 != -1625566762 {
		t.Errorf("mmh3 = %d, want -1625566762", info.MMH3)
	}
	if info.MD5 != "9df540d3548e5524810e26a6f8cbb3cf" {
		t.Errorf("md5 = %s", info.MD5)
	}
	wrapped := string(WrappedBase64(fixture))
	if !strings.HasSuffix(wrapped, "\n") || len(strings.Split(wrapped, "\n")[0]) != 76 {
		t.Errorf("wrapped base64 must be 76-char lines ending in a newline: %q", wrapped[:90])
	}
	if got := info.ShodanQuery(); got != "http.favicon.hash:-1625566762" {
		t.Errorf("shodan query = %s", got)
	}
	if got := info.FOFAQuery(); got != `icon_hash="-1625566762"` {
		t.Errorf("fofa query = %s", got)
	}
}

// Python mmh3.hash (signed) reference values, as gimorra pins them.
func TestMurmur3MatchesTheReference(t *testing.T) {
	for in, want := range map[string]int32{
		"":      0,
		"a":     1009084850,
		"hello": 613153351,
		"The quick brown fox jumps over the lazy dog": 776992547,
	} {
		if got := int32(Murmur3x86_32([]byte(in), 0)); got != want {
			t.Errorf("mmh3(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestLooksLikeIcon(t *testing.T) {
	for _, tc := range []struct {
		body string
		want bool
	}{
		{"\x00\x00\x01\x00\x01\x00", true},
		{"\x89PNG\r\n\x1a\n", true},
		{`<svg xmlns="http://www.w3.org/2000/svg"></svg>`, true},
		{"<!doctype html><html><body>Not Found</body></html>", false},
		{"ab", false},
	} {
		if got := LooksLikeIcon([]byte(tc.body)); got != tc.want {
			t.Errorf("LooksLikeIcon(%q) = %v, want %v", tc.body, got, tc.want)
		}
	}
}
