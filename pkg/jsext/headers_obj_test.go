package jsext

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/grafana/sobek"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/jsext/jsheaders"
)

func hdrs(pairs ...string) []httpmsg.HttpHeader {
	out := make([]httpmsg.HttpHeader, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, httpmsg.HttpHeader{Name: pairs[i], Value: pairs[i+1]})
	}
	return out
}

// headersVM returns a runtime with `h` bound to a header object over hs.
func headersVM(t *testing.T, hs []httpmsg.HttpHeader) *sobek.Runtime {
	t.Helper()
	vm := sobek.New()
	require.NoError(t, vm.Set("h", newHeadersObject(vm, hs)))
	return vm
}

func runJS(t *testing.T, vm *sobek.Runtime, code string) sobek.Value {
	t.Helper()
	v, err := vm.RunString(code)
	require.NoError(t, err, code)
	return v
}

func jsString(t *testing.T, vm *sobek.Runtime, code string) string {
	t.Helper()
	return runJS(t, vm, code).String()
}

func TestHeadersObject_CaseInsensitiveGet(t *testing.T) {
	// HTTP/1.1 canonical case and HTTP/2-style lowercase names read the same.
	for name, hs := range map[string][]httpmsg.HttpHeader{
		"h1": hdrs("Content-Type", "text/html", "X-Frame-Options", "DENY"),
		"h2": hdrs("content-type", "text/html", "x-frame-options", "DENY"),
	} {
		t.Run(name, func(t *testing.T) {
			vm := headersVM(t, hs)
			for _, expr := range []string{`h["content-type"]`, `h["Content-Type"]`, `h["CONTENT-TYPE"]`, `h.get("content-type")`, `h.get("Content-Type")`} {
				assert.Equal(t, "text/html", jsString(t, vm, expr), expr)
			}
			assert.True(t, runJS(t, vm, `"X-Frame-Options" in h && h.has("x-frame-options") && h.hasOwnProperty("x-frame-options")`).ToBoolean())
			assert.True(t, runJS(t, vm, `h["missing"] === undefined && h.get("missing") === null && !h.has("missing") && !("missing" in h)`).ToBoolean())
		})
	}
}

func TestHeadersObject_KeysOrderAndJSON(t *testing.T) {
	vm := headersVM(t, hdrs("Content-Type", "text/html", "Set-Cookie", "a=1", "X-Trace", "1", "set-cookie", "b=2", "Vary", "Accept"))
	assert.Equal(t, "content-type,set-cookie,x-trace,vary", jsString(t, vm, `Object.keys(h).join(",")`))
	assert.Equal(t, "content-type,set-cookie,x-trace,vary", jsString(t, vm, `var ks = []; for (var k in h) ks.push(k); ks.join(",")`))
	// Methods live on the prototype and are not enumerable.
	assert.Equal(t, `{"content-type":"text/html","set-cookie":"b=2","x-trace":"1","vary":"Accept"}`, jsString(t, vm, `JSON.stringify(h)`))
	assert.Equal(t, "text/html|b=2", jsString(t, vm, `var o = JSON.parse(JSON.stringify(h)); o["content-type"] + "|" + o["set-cookie"]`))
	assert.Equal(t, "text/html", jsString(t, vm, `var c = Object.assign({}, h); c["content-type"]`))
}

func TestHeadersObject_Duplicates(t *testing.T) {
	vm := headersVM(t, hdrs("Set-Cookie", "a=1", "Cache-Control", "no-cache", "Set-Cookie", "b=2", "cache-control", "no-store"))
	// set-cookie keeps last-wins for property access and get(); getAll has every value.
	assert.Equal(t, "b=2", jsString(t, vm, `h["Set-Cookie"]`))
	assert.Equal(t, "b=2", jsString(t, vm, `h.get("set-cookie")`))
	assert.Equal(t, `["a=1","b=2"]`, jsString(t, vm, `JSON.stringify(h.getAll("SET-COOKIE"))`))
	// Other repeated headers join with ", " (RFC 9110 §5.3).
	assert.Equal(t, "no-cache, no-store", jsString(t, vm, `h["cache-control"]`))
	assert.Equal(t, `[]`, jsString(t, vm, `JSON.stringify(h.getAll("missing"))`))
	// entries(): original case, every occurrence, wire order. raw(): legacy shape.
	assert.Equal(t, `[["Set-Cookie","a=1"],["Cache-Control","no-cache"],["Set-Cookie","b=2"],["cache-control","no-store"]]`,
		jsString(t, vm, `JSON.stringify(h.entries())`))
	assert.Equal(t, `{"Set-Cookie":"b=2","Cache-Control":"no-cache","cache-control":"no-store"}`, jsString(t, vm, `JSON.stringify(h.raw())`))
}

func TestHeadersObject_MethodNameCollision(t *testing.T) {
	// A server-chosen header name must not be able to replace the methods.
	vm := headersVM(t, hdrs("Get", "evil", "HAS", "evil", "toString", "evil", "X-Frame-Options", "DENY"))
	assert.Equal(t, "function", jsString(t, vm, `typeof h.get`))
	assert.Equal(t, "function", jsString(t, vm, `typeof h["get"]`))
	assert.Equal(t, "function", jsString(t, vm, `typeof h.has`))
	assert.Equal(t, "DENY", jsString(t, vm, `h.get("x-frame-options")`))
	assert.Equal(t, "evil", jsString(t, vm, `h.get("get")`))
	assert.Equal(t, "x-frame-options", jsString(t, vm, `Object.keys(h).join(",")`))
	assert.Equal(t, "[object Object]", jsString(t, vm, `String(h)`))
	assert.Equal(t, "4", jsString(t, vm, `h.entries().length`))
}

func TestHeadersObject_SetDelete(t *testing.T) {
	hs := hdrs("Content-Type", "text/html", "X-A", "1", "x-a", "2")
	vm := sobek.New()
	obj := newHeadersObject(vm, hs)
	require.NoError(t, vm.Set("h", obj))

	runJS(t, vm, `h["Content-Type"] = "application/json"; h["X-New"] = "n"; delete h["x-a"];`)
	assert.Equal(t, "application/json", jsString(t, vm, `h["content-type"]`))
	assert.Equal(t, "n", jsString(t, vm, `h.get("x-new")`))
	assert.True(t, runJS(t, vm, `h["x-a"] === undefined && !h.has("X-A")`).ToBoolean())
	assert.Equal(t, "content-type,x-new", jsString(t, vm, `Object.keys(h).join(",")`))
	runJS(t, vm, `h["x-new"] = undefined`)
	assert.False(t, runJS(t, vm, `h.has("x-new")`).ToBoolean())

	// Only the JS view changes.
	assert.Equal(t, "text/html", hs[0].Value)

	store, ok := jsheaders.FromValue(obj)
	require.True(t, ok)
	set, deleted := store.Changes()
	assert.Equal(t, hdrs("Content-Type", "application/json"), set)
	assert.Equal(t, []string{"x-new", "x-a"}, deleted) // first-touched order

	// A method called on a foreign object throws instead of crashing.
	_, err := vm.RunString(`h.get.call({}, "x")`)
	require.Error(t, err)
}

func TestHeadersArg_MergesCaseInsensitively(t *testing.T) {
	vm := sobek.New()
	require.NoError(t, vm.Set("h", newHeadersObject(vm, hdrs("Authorization", "Bearer old", "Accept", "a", "accept", "b"))))

	// The skill's Object.assign idiom must yield one Authorization header.
	m := headersArg(vm, runJS(t, vm, `Object.assign({}, h, {"Authorization": "Bearer new"})`))
	assert.Equal(t, map[string]string{"Authorization": "Bearer new", "accept": "a, b"}, m)

	// A header object passed straight through keeps original-case names.
	m = headersArg(vm, runJS(t, vm, `h`))
	assert.Equal(t, map[string]string{"Authorization": "Bearer old", "Accept": "a, b"}, m)

	assert.Empty(t, headersArg(vm, sobek.Undefined()))
	assert.True(t, mapHasHeader(map[string]string{"content-length": "3"}, "Content-Length"))
}

func TestBuildRequestContext_HeaderObjects(t *testing.T) {
	vm := sobek.New()
	svc, err := httpmsg.ParseService("http://example.com")
	require.NoError(t, err)
	req := httpmsg.NewHttpRequestWithService(svc, []byte("GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer t\r\n\r\n"))
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nhi"))
	require.NoError(t, vm.Set("ctx", buildRequestContext(vm, httpmsg.NewHttpRequestResponse(req, resp))))

	assert.Equal(t, "Bearer t", jsString(t, vm, `ctx.request.headers.get("authorization")`))
	assert.Equal(t, "Bearer t", jsString(t, vm, `ctx.request.headers["authorization"]`))
	assert.Equal(t, "text/html", jsString(t, vm, `ctx.response.headers["content-type"]`))
	assert.Equal(t, "b=2", jsString(t, vm, `ctx.response.headers["Set-Cookie"]`))
	assert.Equal(t, "2", jsString(t, vm, `ctx.response.headers.getAll("set-cookie").length`))
}

func TestPreHook_HeaderObjectAppliesOnlyChanges(t *testing.T) {
	src := `module.exports = {
  id: "hdr-hook",
  type: "pre_hook",
  execute: function(request) {
    if (request.headers["x-api-key"] !== "k") throw new Error("case-insensitive read failed");
    request.headers["Authorization"] = "Bearer injected";
    delete request.headers["x-debug"];
    return {headers: request.headers};
  }
};`
	meta, err := newMetadataExtractor().Extract(src, "hdr_hook.js")
	require.NoError(t, err)
	hook, err := NewPreHook(&LoadedScript{Path: "hdr_hook.js", Source: src, Metadata: *meta}, APIOptions{})
	require.NoError(t, err)

	svc, err := httpmsg.ParseService("http://example.com")
	require.NoError(t, err)
	req := httpmsg.NewHttpRequestWithService(svc, []byte("GET / HTTP/1.1\r\nHost: example.com\r\nX-Api-Key: k\r\nAccept: a\r\nAccept: b\r\nX-Debug: 1\r\n\r\n"))
	out, err := hook.Execute(httpmsg.NewHttpRequestResponse(req, nil))
	require.NoError(t, err)
	require.NotNil(t, out)

	raw := string(out.Request().Raw())
	assert.Contains(t, raw, "Authorization: Bearer injected\r\n")
	assert.NotContains(t, raw, "X-Debug")
	// Untouched headers keep their case and repeats.
	assert.Contains(t, raw, "X-Api-Key: k\r\nAccept: a\r\nAccept: b\r\n")
}

// presetModule loads a shipped preset from public/presets/extensions.
func presetModule(t *testing.T, file string) *JSPassiveModule {
	t.Helper()
	path := filepath.Join("..", "..", "public", "presets", "extensions", file)
	src, err := os.ReadFile(path)
	require.NoError(t, err)
	meta, err := newMetadataExtractor().Extract(string(src), path)
	require.NoError(t, err)
	mod, err := NewJSPassiveModule(&LoadedScript{Path: path, Source: string(src), Metadata: *meta}, APIOptions{})
	require.NoError(t, err)
	return mod
}

func rrWithResponse(t *testing.T, rawResp string) *httpmsg.HttpRequestResponse {
	t.Helper()
	svc, err := httpmsg.ParseService("http://example.com")
	require.NoError(t, err)
	req := httpmsg.NewHttpRequestWithService(svc, []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	return httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse([]byte(rawResp)))
}

// TestPresets_CanonicalCaseHeaders is the regression for the header-case bug:
// the presets read lowercase names, and servers send canonical case.
func TestPresets_CanonicalCaseHeaders(t *testing.T) {
	cases := []struct {
		file  string
		resp  string
		fires bool
	}{
		{"csp_directive_evaluator.js", "HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src *; script-src 'unsafe-inline'\r\nContent-Type: text/html\r\n\r\n<html></html>", true},
		{"verbose_json_fields.js", "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"password_hash\": \"x\"}", true},
		{"webhook_callback_detector.js", "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"webhook_url\": \"https://hooks.example.org/x\"}", true},
		{"internal_url_leak.js", "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<a href=\"http://db.internal/x\">x</a>", true},
		// The Content-Type skip list must apply with canonical-case headers.
		{"internal_url_leak.js", "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nvar u = \"http://db.internal/x\";", false},
		{"sensitive_data_exposure.js", "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nkey AKIAABCDEFGHIJKLMNOP here", true},
		{"sensitive_data_exposure.js", "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nvar k = \"AKIAABCDEFGHIJKLMNOP\";", false},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			mod := presetModule(t, tc.file)
			results, err := mod.ScanPerRequest(rrWithResponse(t, tc.resp), nil)
			require.NoError(t, err)
			if tc.fires {
				assert.NotEmpty(t, results, "preset should fire")
			} else {
				assert.Empty(t, results, "preset should skip this content type")
			}
		})
	}
}

// TestSkillExample_HeaderCheck runs the passive example from the skill
// reference and checks it no longer flags a response that sets the headers in
// canonical case.
func TestSkillExample_HeaderCheck(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "public", "skills", "vigolium-scanner", "references", "extensions.md"))
	require.NoError(t, err)
	var src string
	for _, m := range regexp.MustCompile("(?s)```javascript\n(.*?)```").FindAllStringSubmatch(string(doc), -1) {
		if strings.Contains(m[1], `id: "header-check"`) {
			src = m[1]
			break
		}
	}
	require.NotEmpty(t, src, "header-check example not found in the skill reference")
	require.Contains(t, src, `headers.get("x-frame-options")`, "the example should use the documented headers.get() idiom")

	meta, err := newMetadataExtractor().Extract(src, "header_check.js")
	require.NoError(t, err)
	mod, err := NewJSPassiveModule(&LoadedScript{Path: "header_check.js", Source: src, Metadata: *meta}, APIOptions{})
	require.NoError(t, err)

	results, err := mod.ScanPerRequest(rrWithResponse(t, "HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\nStrict-Transport-Security: max-age=31536000\r\n\r\nok"), nil)
	require.NoError(t, err)
	assert.Empty(t, results)

	results, err = mod.ScanPerRequest(rrWithResponse(t, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nok"), nil)
	require.NoError(t, err)
	assert.NotEmpty(t, results)
}

var benchHeaders = hdrs(
	"Date", "Mon, 01 Jan 2026 00:00:00 GMT", "Content-Type", "text/html; charset=utf-8",
	"Content-Length", "1234", "Connection", "keep-alive", "Cache-Control", "no-cache",
	"Set-Cookie", "a=1; Path=/", "Set-Cookie", "b=2; Path=/", "X-Frame-Options", "DENY",
	"Strict-Transport-Security", "max-age=31536000", "Content-Security-Policy", "default-src 'self'",
	"Server", "nginx", "Vary", "Accept-Encoding",
)

const benchScript = `(function(h){ var n = 0;
  if (h["content-type"]) n++; if (h["x-frame-options"]) n++; if (!h["x-missing"]) n++;
  if (h["content-security-policy"]) n++; return n; })`

// BenchmarkHeaders compares a realistic extension access pattern (build the
// object, read a few names) against the old plain object.
func BenchmarkHeaders(b *testing.B) {
	run := func(b *testing.B, build func(vm *sobek.Runtime) sobek.Value) {
		vm := sobek.New()
		fnVal, err := vm.RunString(benchScript)
		if err != nil {
			b.Fatal(err)
		}
		fn, _ := sobek.AssertFunction(fnVal)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := fn(sobek.Undefined(), build(vm)); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.Run("plain", func(b *testing.B) {
		run(b, func(vm *sobek.Runtime) sobek.Value {
			o := vm.NewObject()
			for _, h := range benchHeaders {
				_ = o.Set(strings.ToLower(h.Name), h.Value)
			}
			return o
		})
	})
	b.Run("dynamic", func(b *testing.B) {
		run(b, func(vm *sobek.Runtime) sobek.Value { return newHeadersObject(vm, benchHeaders) })
	})
}
