package httpmsg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnsureURLScheme(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"example.com", "http://example.com"},
		// A bare host:port is the shape net/url reads as a path segment with a
		// colon in it, which is what broke the browser phase.
		{"example.com:8443", "http://example.com:8443"},
		{"//example.com", "http://example.com"},
		{"https://example.com:8443/a?b=1", "https://example.com:8443/a?b=1"},
		// "://" inside the query is not a scheme.
		{"example.com/r?u=http://inner", "http://example.com/r?u=http://inner"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, EnsureURLScheme(tc.in, DefaultTargetScheme), "target %q", tc.in)
	}

	assert.Equal(t, "https://example.com", EnsureURLScheme("example.com", "https"),
		"the default scheme is the caller's choice")
}
