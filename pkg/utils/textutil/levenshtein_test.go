package textutil

import "testing"

func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"module", "module", 0},
		{"module", "modules", 1},
		{"modul", "modules", 2},
		{"", "abc", 3},
		{"abc", "", 3},
		{"kitten", "sitting", 3},
		{"url", "all", 2},
		{"héllo", "hello", 1},
	}
	for _, tc := range cases {
		if got := Levenshtein(tc.a, tc.b); got != tc.want {
			t.Errorf("Levenshtein(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
