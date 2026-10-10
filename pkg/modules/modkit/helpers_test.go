package modkit

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateVariants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, got, want string
	}{
		{"fits", Truncate("abc", 5), "abc"},
		{"exact", Truncate("abcde", 5), "abcde"},
		{"cut", Truncate("abcdefghij", 5), "abcde..."},
		{"with suffix", TruncateWith("abcdefghij", 5, "…"), "abcde…"},
		{"no ellipsis", TruncateNoEllipsis("abcdefghij", 5), "abcde"},
		{"no ellipsis fits", TruncateNoEllipsis("abc", 5), "abc"},
		// "é" is 2 bytes: a 4-byte cut would split the second one.
		{"rune safe", Truncate("éée", 3), "é..."},
		{"runes fit", TruncateRunes("ééé", 3, "…"), "ééé"},
		{"runes cut", TruncateRunes("éééé", 3, "…"), "ééé…"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, c.got, c.want)
		}
		if !utf8.ValidString(c.got) {
			t.Errorf("%s: invalid UTF-8 %q", c.name, c.got)
		}
	}
}

func TestRandomAlnum(t *testing.T) {
	t.Parallel()
	const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	a, b := RandomAlnum(16), RandomAlnum(16)
	if len(a) != 16 || len(b) != 16 {
		t.Fatalf("lengths %d/%d, want 16", len(a), len(b))
	}
	if a == b {
		t.Errorf("two back-to-back tokens are equal: %q", a)
	}
	for _, c := range a + b {
		if !strings.ContainsRune(alnum, c) {
			t.Errorf("non-alphanumeric char %q", c)
		}
	}
	if RandomAlnum(0) != "" {
		t.Error("RandomAlnum(0) should be empty")
	}
}

func TestIsStaticAssetContentType(t *testing.T) {
	t.Parallel()
	static := []string{
		"text/javascript",
		"application/javascript; charset=utf-8",
		"application/x-javascript",
		"text/css",
		"image/png",
		"image/svg+xml",
		"font/woff2",
		"application/font-woff",
		"video/mp4",
		"audio/mpeg",
		"application/wasm",
		"application/octet-stream",
		"application/pdf",
		"application/zip",
		"application/gzip",
	}
	for _, ct := range static {
		if !IsStaticAssetContentType(ct) {
			t.Errorf("IsStaticAssetContentType(%q) = false, want true", ct)
		}
	}

	notStatic := []string{
		"",
		"application/json",
		"application/json; charset=utf-8",
		"text/html",
		"text/plain",
		"application/xml",
		"text/event-stream",
		"application/vnd.api+json",
	}
	for _, ct := range notStatic {
		if IsStaticAssetContentType(ct) {
			t.Errorf("IsStaticAssetContentType(%q) = true, want false", ct)
		}
	}
}

func TestIsStaticAssetPath(t *testing.T) {
	t.Parallel()
	static := []string{
		"/css/images", "/assets/app", "/static/main", "/js/vendor",
		"/img/logo", "/bundles/app.css", "/x/y.png", "/_next/data/x",
		"/wp-content/uploads/file", "/fonts/inter", "/MEDIA/clip",
		"/app.js", "/styles/site",
	}
	for _, p := range static {
		if !IsStaticAssetPath(p) {
			t.Errorf("IsStaticAssetPath(%q) = false, want true", p)
		}
	}
	dynamic := []string{
		"/account/profile", "/api/me", "/dashboard", "/blog/post-1",
		"/", "/users/123", "/cssselector", "/imagine",
	}
	for _, p := range dynamic {
		if IsStaticAssetPath(p) {
			t.Errorf("IsStaticAssetPath(%q) = true, want false", p)
		}
	}
}
