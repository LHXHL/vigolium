package terminal

import (
	"testing"
	"unicode/utf8"

	"github.com/mattn/go-runewidth"
)

func TestTruncate(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		width int
		want  string
	}{
		{"fits", "hello", 10, "hello"},
		{"exact", "hello", 5, "hello"},
		{"ascii cut", "hello world", 6, "hello…"},
		{"tiny width", "hello", 1, "…"},
		{"zero width", "hello", 0, "…"},
		// Each CJK rune is two columns wide: 5 columns hold two runes + "…".
		{"wide runes", "日本語テキスト", 5, "日本…"},
		{"multibyte narrow", "éééééé", 4, "ééé…"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Truncate(tt.in, tt.width)
			if got != tt.want {
				t.Errorf("Truncate(%q, %d) = %q, want %q", tt.in, tt.width, got, tt.want)
			}
			if !utf8.ValidString(got) {
				t.Errorf("Truncate(%q, %d) produced invalid UTF-8", tt.in, tt.width)
			}
			if tt.width >= 1 && runewidth.StringWidth(got) > tt.width {
				t.Errorf("Truncate(%q, %d) = %q is %d columns wide", tt.in, tt.width, got, runewidth.StringWidth(got))
			}
		})
	}
}
