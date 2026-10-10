package httpmsg_test

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/curl"
)

type curlCase struct {
	name    string
	raw     string
	target  string
	opts    httpmsg.CurlOptions
	method  string
	url     string
	headers map[string]string // must be present after the round trip
	absent  []string          // must not be present after the round trip
	body    string
	hints   func(t *testing.T, h curl.TransportHints)
}

func curlCorpus() []curlCase {
	multipart := "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--XyZ--\r\n"
	quoted := `{"q":"it's $HOME ` + "`id`" + ` \\ \"x\"","n":"line1
line2"}`
	return []curlCase{
		{
			name:    "get with query",
			raw:     "GET /search?q=a%20b&x=1 HTTP/1.1\r\nHost: shop.test\r\nAccept: */*\r\nX-Trace: 'quoted'\r\n\r\n",
			target:  "https://shop.test:443",
			method:  "GET",
			url:     "https://shop.test/search?q=a%20b&x=1",
			headers: map[string]string{"Accept": "*/*", "X-Trace": "'quoted'"},
		},
		{
			name:    "json post",
			raw:     "POST /api/users HTTP/1.1\r\nHost: api.test:8443\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"name\":\"alice\"}",
			target:  "https://api.test:8443",
			method:  "POST",
			url:     "https://api.test:8443/api/users",
			headers: map[string]string{"Content-Type": "application/json"},
			body:    `{"name":"alice"}`,
		},
		{
			name:    "multipart",
			raw:     "POST /upload HTTP/1.1\r\nHost: up.test\r\nContent-Type: multipart/form-data; boundary=XyZ\r\n\r\n" + multipart,
			target:  "http://up.test",
			method:  "POST",
			url:     "http://up.test/upload",
			headers: map[string]string{"Content-Type": "multipart/form-data; boundary=XyZ"},
			body:    multipart,
		},
		{
			name:    "quotes and shell metacharacters in body",
			raw:     "PUT /notes/7 HTTP/1.1\r\nHost: n.test\r\nContent-Type: application/json\r\n\r\n" + quoted,
			target:  "http://n.test",
			method:  "PUT",
			url:     "http://n.test/notes/7",
			headers: map[string]string{"Content-Type": "application/json"},
			body:    quoted,
		},
		{
			name:    "vhost mismatch keeps the Host header",
			raw:     "GET /admin HTTP/1.1\r\nHost: internal.vhost\r\n\r\n",
			target:  "http://10.0.0.5:8080",
			method:  "GET",
			url:     "http://10.0.0.5:8080/admin",
			headers: map[string]string{"Host": "internal.vhost"},
		},
		{
			name:   "h2 with compression and dot segments",
			raw:    "GET /static/../etc/passwd HTTP/2\r\nHost: h2.test\r\nAccept-Encoding: gzip, br\r\n\r\n",
			target: "https://h2.test",
			method: "GET",
			url:    "https://h2.test/static/../etc/passwd",
			hints: func(t *testing.T, h curl.TransportHints) {
				if h.HTTPVersion != "2" || !h.Compressed || !h.PathAsIs {
					t.Errorf("hints = %+v, want --http2 --compressed --path-as-is", h)
				}
			},
		},
		{
			name:   "delete without body",
			raw:    "DELETE /items/3 HTTP/1.1\r\nHost: d.test\r\n\r\n",
			target: "https://d.test",
			method: "DELETE",
			url:    "https://d.test/items/3",
		},
		{
			name:   "get with body",
			raw:    "GET /q HTTP/1.1\r\nHost: g.test\r\nContent-Type: text/plain\r\n\r\nhello",
			target: "https://g.test",
			method: "GET",
			url:    "https://g.test/q",
			body:   "hello",
		},
		{
			name:    "body starting with @",
			raw:     "POST /mention HTTP/1.1\r\nHost: m.test\r\nContent-Type: text/plain\r\n\r\n@etc/passwd",
			target:  "https://m.test",
			method:  "POST",
			url:     "https://m.test/mention",
			headers: map[string]string{"Content-Type": "text/plain"},
			body:    "@etc/passwd",
		},
		{
			name:    "redacted credentials",
			raw:     "GET /me HTTP/1.1\r\nHost: r.test\r\nAuthorization: Bearer abc\r\nCookie: sid=1\r\nX-Keep: v\r\n\r\n",
			target:  "https://r.test",
			opts:    httpmsg.CurlOptions{RedactAuth: true, Insecure: true},
			method:  "GET",
			url:     "https://r.test/me",
			headers: map[string]string{"Authorization": "<redacted>", "Cookie": "<redacted>", "X-Keep": "v"},
			hints: func(t *testing.T, h curl.TransportHints) {
				if !h.Insecure {
					t.Errorf("hints = %+v, want -k", h)
				}
			},
		},
		{
			name:   "absolute-form request line, braces in path",
			raw:    "GET http://proxy.test/users/{id}?a[]=1 HTTP/1.1\r\nHost: proxy.test\r\n\r\n",
			target: "",
			method: "GET",
			url:    "http://proxy.test/users/{id}?a[]=1",
		},
	}
}

// TestToCurlRoundTrip renders each request and parses the command back with
// the curl input parser: method, URL, headers and body must survive.
func TestToCurlRoundTrip(t *testing.T) {
	for _, tc := range curlCorpus() {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := httpmsg.ToCurl([]byte(tc.raw), tc.target, tc.opts)
			if err != nil {
				t.Fatalf("ToCurl: %v", err)
			}
			if cmd.StdinBase64 != "" {
				t.Fatalf("text body went through the base64 pipe: %s", cmd.Command)
			}
			rr, hints, err := curl.ParseSingleCommandWithHints(cmd.Command)
			if err != nil {
				t.Fatalf("parse %q: %v", cmd.Command, err)
			}
			req := rr.Request()
			if req.Method() != tc.method {
				t.Errorf("method = %q, want %q (cmd: %s)", req.Method(), tc.method, cmd.Command)
			}
			u, err := rr.URL()
			if err != nil {
				t.Fatalf("url: %v", err)
			}
			if got := u.String(); got != tc.url {
				t.Errorf("url = %q, want %q", got, tc.url)
			}
			for name, want := range tc.headers {
				got := ""
				for _, h := range req.Headers() {
					if strings.EqualFold(h.Name, name) {
						got = h.Value // last wins: a kept vhost follows the parser's own Host
					}
				}
				if got != want {
					t.Errorf("header %s = %q, want %q (cmd: %s)", name, got, want, cmd.Command)
				}
			}
			if got := string(req.Body()); got != tc.body {
				t.Errorf("body = %q, want %q", got, tc.body)
			}
			if tc.hints != nil {
				tc.hints(t, hints)
			}
		})
	}
}

func TestToCurlShape(t *testing.T) {
	cmd, err := httpmsg.ToCurl([]byte("GET / HTTP/1.1\r\nHost: a.test\r\nContent-Length: 0\r\n\r\n"), "https://a.test", httpmsg.CurlOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Command != "curl -sS https://a.test/" {
		t.Errorf("command = %q", cmd.Command)
	}
	if strings.Contains(cmd.Command, "-X") || strings.Contains(cmd.Command, "Content-Length") || strings.Contains(cmd.Command, "Host:") {
		t.Errorf("GET must omit -X, Content-Length and a matching Host: %q", cmd.Command)
	}

	head, err := httpmsg.ToCurl([]byte("HEAD /x HTTP/1.1\r\nHost: a.test\r\n\r\n"), "http://a.test:80", httpmsg.CurlOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if head.Command != "curl -sS -I http://a.test/x" {
		t.Errorf("HEAD = %q", head.Command)
	}

	creds, err := httpmsg.ToCurl([]byte("GET / HTTP/1.1\r\nHost: a.test\r\nCookie: s=1\r\n\r\n"), "https://a.test", httpmsg.CurlOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !creds.Credentials || creds.Redacted {
		t.Errorf("credentials=%v redacted=%v, want true/false", creds.Credentials, creds.Redacted)
	}

	if _, err := httpmsg.ToCurl([]byte("GET / HTTP/1.1\r\nHost: a.test\r\n\r\n"), "", httpmsg.CurlOptions{}); err == nil {
		t.Error("an origin-form request with no target URL must be refused, not guessed from Host")
	}
}

// TestToCurlBinaryBody: a non-text body goes through the base64 pipe and
// decodes back to the exact bytes.
func TestToCurlBinaryBody(t *testing.T) {
	body := []byte{0x00, 0x01, 0xff, 'a', '\'', 0x7f}
	raw := append([]byte("POST /bin HTTP/1.1\r\nHost: b.test\r\nContent-Type: application/octet-stream\r\n\r\n"), body...)
	cmd, err := httpmsg.ToCurl(raw, "https://b.test", httpmsg.CurlOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.StdinBase64 == "" {
		t.Fatalf("binary body not piped: %s", cmd.Command)
	}
	decoded, err := base64.StdEncoding.DecodeString(cmd.StdinBase64)
	if err != nil || !bytes.Equal(decoded, body) {
		t.Fatalf("stdin payload = %v (%v), want %v", decoded, err, body)
	}
	if !strings.HasPrefix(cmd.Command, "printf '%s' ") || !strings.Contains(cmd.Command, "| base64 --decode | curl ") {
		t.Errorf("command = %q", cmd.Command)
	}
	if got := cmd.Argv[len(cmd.Argv)-2]; got != "@-" {
		t.Errorf("argv data = %q, want @-", got)
	}

	sh := shellPath(t)
	if _, err := exec.LookPath("base64"); err != nil {
		t.Skip("base64 not available")
	}
	pipe := cmd.Command[:strings.Index(cmd.Command, "| curl ")]
	out, err := exec.Command(sh, "-c", pipe).Output()
	if err != nil {
		t.Fatalf("run %q: %v", pipe, err)
	}
	if !bytes.Equal(out, body) {
		t.Errorf("pipe produced %v, want %v", out, body)
	}
}

// TestToCurlShellResplit: every argv element survives a real /bin/sh re-split
// of Command — quotes, $, backticks, backslashes and newlines included.
func TestToCurlShellResplit(t *testing.T) {
	sh := shellPath(t)
	nasty := []string{
		`it's`, `$(id)`, "`id`", `\n\t`, "a\nb", `"dq"`, `!x`, `*`, `~`, `;rm -rf /`, `''`, `%2f`, "tab\there",
	}
	for _, v := range nasty {
		raw := "POST /p?x=" + "1" + " HTTP/1.1\r\nHost: s.test\r\nX-V: " + strings.ReplaceAll(v, "\n", " ") + "\r\nContent-Type: text/plain\r\n\r\n" + v
		cmd, err := httpmsg.ToCurl([]byte(raw), "https://s.test", httpmsg.CurlOptions{})
		if err != nil {
			t.Fatalf("ToCurl(%q): %v", v, err)
		}
		// Replace the program with printf so the shell prints the argv it built.
		script := "printf '%s\\0'" + strings.TrimPrefix(cmd.Command, "curl")
		out, err := exec.Command(sh, "-c", script).Output()
		if err != nil {
			t.Fatalf("sh -c %q: %v", script, err)
		}
		got := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
		want := cmd.Argv[1:]
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("value %q: shell re-split\n got  %q\n want %q", v, got, want)
		}
	}
}

func shellPath(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"/bin/sh", "/usr/bin/sh"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("no POSIX shell available")
	return ""
}
