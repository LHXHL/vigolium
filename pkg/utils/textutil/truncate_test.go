package textutil

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateUTF8(t *testing.T) {
	tests := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"fits", "hello", 10, "hello"},
		{"exact", "hello", 5, "hello"},
		{"ascii cut", "hello world", 5, "hello"},
		{"zero", "hello", 0, ""},
		{"negative", "hello", -1, ""},
		// "é" is 2 bytes; cutting at 2 would split it.
		{"two-byte rune not split", "aé", 2, "a"},
		{"two-byte rune kept", "aé", 3, "aé"},
		// "日本" is 3 bytes per rune.
		{"three-byte rune not split", "日本", 4, "日"},
		{"three-byte rune boundary", "日本", 3, "日"},
		{"less than one rune", "日本", 2, ""},
		// emoji is 4 bytes.
		{"four-byte rune not split", "x\U0001F600y", 4, "x"},
		{"invalid byte replaced", "a\xffb", 10, "a�b"},
		{"invalid byte replacement respects bound", "a\xffb", 3, "a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TruncateUTF8(tt.in, tt.max)
			if got != tt.want {
				t.Errorf("TruncateUTF8(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
			}
		})
	}
}

func TestCutIndexBytesUntouched(t *testing.T) {
	// Non-UTF-8 binary data: the cut lands at maxBytes and nothing is rewritten.
	b := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}
	if got := CutIndex(b, 5); got != 5 {
		t.Errorf("CutIndex(binary, 5) = %d, want 5", got)
	}
	if got := CutIndex([]byte("aé"), 2); got != 1 {
		t.Errorf("CutIndex(aé, 2) = %d, want 1", got)
	}
	if got := CutIndex("abc", 10); got != 3 {
		t.Errorf("CutIndex(abc, 10) = %d, want 3", got)
	}
}

func TestTruncateRunes(t *testing.T) {
	tests := []struct {
		in   string
		max  int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello", 3, "hel"},
		{"日本語テキスト", 3, "日本語"},
		{"x\U0001F600y", 2, "x\U0001F600"},
		{"abc", 0, ""},
		{"a\xffbc", 2, "a�"},
	}
	for _, tt := range tests {
		if got := TruncateRunes(tt.in, tt.max); got != tt.want {
			t.Errorf("TruncateRunes(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
		}
	}
}

func TestTruncateEllipsis(t *testing.T) {
	if got := TruncateUTF8Ellipsis("hello world", 8, "..."); got != "hello..." {
		t.Errorf("got %q", got)
	}
	if got := TruncateUTF8Ellipsis("日本語", 7, "..."); got != "日..." {
		t.Errorf("got %q", got)
	}
	if got := TruncateUTF8Ellipsis("hello", 2, "..."); got != "he" {
		t.Errorf("tiny bound should drop the ellipsis, got %q", got)
	}
	if got := TruncateRunesEllipsis("日本語テキスト", 4, "…"); got != "日本語…" {
		t.Errorf("got %q", got)
	}
	if got := TruncateRunesEllipsis("short", 10, "…"); got != "short" {
		t.Errorf("got %q", got)
	}
}

func FuzzTruncateUTF8(f *testing.F) {
	for _, seed := range []string{"", "hello", "aé", "日本語", "x\U0001F600y", "a\xffb", "\xe6\x97", strings.Repeat("é", 50)} {
		f.Add(seed, 3)
	}
	f.Fuzz(func(t *testing.T, s string, n int) {
		if n > 1<<16 {
			n %= 1 << 16
		}
		got := TruncateUTF8(s, n)
		if !utf8.ValidString(got) {
			t.Fatalf("TruncateUTF8(%q, %d) = %q is not valid UTF-8", s, n, got)
		}
		if n >= 0 && len(got) > n {
			t.Fatalf("TruncateUTF8(%q, %d) = %q exceeds the bound", s, n, got)
		}
		if utf8.ValidString(s) {
			if !strings.HasPrefix(s, got) {
				t.Fatalf("TruncateUTF8(%q, %d) = %q is not a prefix of valid input", s, n, got)
			}
			// It keeps as much as fits: the next rune would cross the bound.
			if len(got) < len(s) {
				_, size := utf8.DecodeRuneInString(s[len(got):])
				if len(got)+size <= n {
					t.Fatalf("TruncateUTF8(%q, %d) = %q dropped a rune that fits", s, n, got)
				}
			}
		}

		r := TruncateRunes(s, n)
		if !utf8.ValidString(r) {
			t.Fatalf("TruncateRunes(%q, %d) = %q is not valid UTF-8", s, n, r)
		}
		if n >= 0 && utf8.RuneCountInString(r) > n {
			t.Fatalf("TruncateRunes(%q, %d) = %q exceeds the rune bound", s, n, r)
		}

		e := TruncateUTF8Ellipsis(s, n, "...")
		if !utf8.ValidString(e) || (n >= 0 && len(e) > n) {
			t.Fatalf("TruncateUTF8Ellipsis(%q, %d) = %q invalid or over bound", s, n, e)
		}
	})
}
