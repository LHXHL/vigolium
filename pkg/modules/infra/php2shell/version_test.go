package php2shell

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerdictFor(t *testing.T) {
	t.Parallel()

	cases := []struct {
		header string
		want   Verdict
		fixed  string
	}{
		{"PHP/8.3.35", Vulnerable, "8.3.36"},
		{"PHP/8.3.36", Fixed, "8.3.36"},
		{"PHP/8.2.34", Vulnerable, "8.2.35"},
		{"PHP/8.4.27", Fixed, "8.4.27"},
		{"PHP/8.5.11", Vulnerable, "8.5.12"},
		{"php/8.5.13", Fixed, "8.5.12"},
		{"PHP/7.4.33", Unknown, ""}, // EOL branch: not judged
		{"PHP/8.3", Unknown, ""},    // no patch number
		{"Express", Unknown, ""},
		{"", Unknown, ""},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, VerdictFor(tc.header), tc.header)
		assert.Equal(t, tc.fixed, FixedRelease(tc.header), tc.header)
	}
	assert.Equal(t, "8.3.35", Version("PHP/8.3.35"))
	assert.Equal(t, "", Version("PHP/8"))
}
