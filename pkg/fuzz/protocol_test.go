package fuzz

import (
	"strings"
	"testing"
)

func TestMultiplexBlocker(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		sel      Selectors
		payloads []string
		blocked  string // substring of the reason; "" = multiplexable
	}{
		{"path marker", "GET /FUZZ HTTP/1.1\r\nHost: a.test\r\n\r\n", Selectors{}, []string{"admin", "x y"}, ""},
		{"query params", "GET /s?q=1&id=2 HTTP/1.1\r\nHost: a.test\r\n\r\n", Selectors{Mode: "params"}, []string{"'"}, ""},
		{"captured keep-alive", "GET /FUZZ HTTP/1.1\r\nHost: a.test\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\n\r\n", Selectors{}, []string{"a"}, ""},
		{"json body marker", "POST /api HTTP/1.1\r\nHost: a.test\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"q\":\"FUZZ\"}", Selectors{}, []string{"a"}, ""},
		{"header value marker", "GET / HTTP/1.1\r\nHost: a.test\r\nX-Api-Version: FUZZ\r\n\r\n", Selectors{}, []string{"v2"}, ""},
		{"host marker", "GET / HTTP/1.1\r\nHost: FUZZ.a.test\r\n\r\n", Selectors{}, []string{"dev"}, "Host header"},
		{"header name marker", "GET / HTTP/1.1\r\nHost: a.test\r\nX-FUZZ: 1\r\n\r\n", Selectors{}, []string{"Forwarded"}, "header name"},
		{"upgrade in request", "GET /FUZZ HTTP/1.1\r\nHost: a.test\r\nUpgrade: websocket\r\n\r\n", Selectors{}, []string{"a"}, "Upgrade"},
		{"hop-by-hop nomination", "GET /FUZZ HTTP/1.1\r\nHost: a.test\r\nConnection: close, X-Real-IP\r\n\r\n", Selectors{}, []string{"a"}, "hop-by-hop"},
		{"connection value marker", "GET / HTTP/1.1\r\nHost: a.test\r\nConnection: FUZZ\r\n\r\n", Selectors{}, []string{"X-Real-IP"}, "hop-by-hop"},
		{"crlf payload", "GET /?q=FUZZ HTTP/1.1\r\nHost: a.test\r\n\r\n", Selectors{}, []string{"a\r\nSet-Cookie: x=1"}, "CR, LF or NUL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(tc.raw)
			positions, err := ResolvePositions(raw, tc.sel)
			if err != nil {
				t.Fatal(err)
			}
			jobCases, err := BuildCases(ModeSniper, positions, nil, tc.payloads)
			if err != nil {
				t.Fatal(err)
			}
			got := MultiplexBlocker(raw, positions, jobCases)
			switch {
			case tc.blocked == "" && got != "":
				t.Errorf("blocked (%q), want multiplexable", got)
			case tc.blocked != "" && !strings.Contains(got, tc.blocked):
				t.Errorf("reason = %q, want one mentioning %q", got, tc.blocked)
			}
		})
	}
}
