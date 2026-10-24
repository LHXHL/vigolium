package brotli_request_decoding_exposure

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// decode undoes a br/gzip Content-Encoding list, last-applied first. ok is
// false for any other coding, or bytes that fail to decode.
func decode(body []byte, encoding string) ([]byte, bool) {
	if encoding == "" {
		return body, true
	}
	codings := strings.Split(encoding, ",")
	for i := len(codings) - 1; i >= 0; i-- {
		var r io.Reader
		switch strings.TrimSpace(codings[i]) {
		case "br":
			r = brotli.NewReader(bytes.NewReader(body))
		case "gzip":
			zr, err := gzip.NewReader(bytes.NewReader(body))
			if err != nil {
				return nil, false
			}
			r = zr
		default:
			return nil, false
		}
		out, err := io.ReadAll(r)
		if err != nil {
			return nil, false
		}
		body = out
	}
	return body, true
}

// handleItems is a JSON route handler: malformed JSON is 400, an object
// without name is 422.
func handleItems(w http.ResponseWriter, body []byte) {
	var v map[string]any
	if err := json.Unmarshal(body, &v); err != nil {
		http.Error(w, `{"error":"invalid JSON: unexpected end of input"}`, http.StatusBadRequest)
		return
	}
	if _, ok := v["name"]; !ok {
		http.Error(w, `{"error":"field name is required"}`, http.StatusUnprocessableEntity)
		return
	}
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// nodeApp mimics body-parser: an unknown encoding is 415 before the body is
// read, a known one that fails to decode is 400. With global set the parser
// runs on every route (NestJS, app.use(express.json())); otherwise only on
// /upload. body-parser 1.x does not know br.
func nodeApp(supportsBrotli, global bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if global || r.URL.Path == "/upload" {
			enc := r.Header.Get("Content-Encoding")
			if strings.Contains(enc, ",") || (enc != "" && enc != "br" && enc != "gzip") || (enc == "br" && !supportsBrotli) {
				http.Error(w, `UnsupportedMediaTypeError: unsupported content encoding "`+enc+`"`, http.StatusUnsupportedMediaType)
				return
			}
			body, ok := decode(raw, enc)
			if !ok {
				http.Error(w, "Error: Decompression failed", http.StatusBadRequest)
				return
			}
			if !json.Valid(body) {
				http.Error(w, "SyntaxError: Unexpected end of JSON input", http.StatusBadRequest)
				return
			}
			raw = body
		}
		if r.URL.Path != "/upload" {
			http.Error(w, "Cannot POST "+r.URL.Path, http.StatusNotFound)
			return
		}
		handleItems(w, raw)
	})
}

// pythonApp ignores Content-Encoding entirely, as Flask, Django and FastAPI
// do: it parses whatever bytes arrive, and only /api/items reads a body.
var pythonApp = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	w.Header().Set("Server", "gunicorn")
	if r.URL.Path != "/api/items" {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	handleItems(w, raw)
})

// envoyFront mimics an Envoy Brotli decompressor (request direction on): it
// decodes br, strips Content-Encoding, and passes other encodings through.
func envoyFront(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "envoy")
		w.Header().Set("X-Envoy-Upstream-Service-Time", "3")
		if r.Header.Get("Content-Encoding") == "br" {
			raw, _ := io.ReadAll(r.Body)
			body, ok := decode(raw, "br")
			if !ok {
				http.Error(w, "decompression failed", http.StatusBadRequest)
				return
			}
			r.Header.Del("Content-Encoding")
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		}
		next.ServeHTTP(w, r)
	})
}

func serve(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func scanCtxFor(srvURL, tag string) *modkit.ScanContext {
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}
	if tag != "" {
		sc.MarkTech(strings.TrimPrefix(srvURL, "http://"), tag)
	}
	return sc
}

// The host lane finds an app-wide parser on the unrouted path.
func TestScanPerHost_AppWideParser(t *testing.T) {
	t.Parallel()
	var hits int64
	var mu sync.Mutex
	var decoys []string
	app := nodeApp(true, true)
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		if v := r.Header.Get(decoyHeader); v != "" {
			mu.Lock()
			decoys = append(decoys, v)
			mu.Unlock()
		}
		app.ServeHTTP(w, r)
	}))

	rr := modtest.Request(t, srv.URL+"/")
	res, err := New().ScanPerHost(rr, modtest.Requester(t), scanCtxFor(srv.URL, "nestjs"))
	require.NoError(t, err)
	require.Len(t, res, 1)

	r := res[0]
	assert.Equal(t, output.RecordKindCandidate, r.RecordKind)
	assert.False(t, r.IsFinding())
	assert.Equal(t, severity.Info, r.Info.Severity)
	assert.Equal(t, severity.Tentative, r.Info.Confidence)
	assert.Equal(t, srv.URL+probePath, r.URL)
	assert.Contains(t, r.Info.Name, "CVE-2026-111497")
	assert.Contains(t, r.Request, "Content-Encoding: br")
	assert.Contains(t, r.AdditionalEvidence[0], "Content-Encoding: "+unknownEncoding)
	assert.Equal(t, "Node.js app (body parser)", r.Metadata["decoder"])
	// {}, {, then br {} and br { twice, the unknown-encoding control and the
	// two header decoys.
	assert.EqualValues(t, 9, atomic.LoadInt64(&hits))
	// One decoy carries a random value, the other names the encoding.
	require.Len(t, decoys, 2)
	assert.Len(t, decoys[0], 12)
	assert.NotEqual(t, "br", decoys[0])
	assert.Equal(t, "br", decoys[1])
	assert.Contains(t, strings.Join(r.ExtractedResults, "\n"), decoyHeader+": br, same bytes, no Content-Encoding")
}

// A parser mounted on one route is invisible to the unrouted probe; the
// recorded JSON request finds it.
func TestScanPerRequest_RouteScopedParser(t *testing.T) {
	t.Parallel()
	srv := serve(t, nodeApp(true, false))
	sc := scanCtxFor(srv.URL, "express")
	client := modtest.Requester(t)

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL+"/"), client, sc)
	require.NoError(t, err)
	assert.Empty(t, res, "the unrouted path answers 404 whatever the body")

	res, err = New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), client, sc)
	require.NoError(t, err)
	assert.Empty(t, res, "a GET record has no route parser to probe")

	res, err = New().ScanPerRequest(modtest.RequestJSON(t, srv.URL+"/upload", `{"name":"a"}`), client, sc)
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, srv.URL+"/upload", res[0].URL)
	assert.Equal(t, "route body parser", res[0].Metadata["lane"])
}

// An Envoy decompressor in front of a Python app that never decodes is the
// exposure the old Node-only gate missed. No tech tag is needed.
func TestScanPerRequest_EnvoyInFrontOfPython(t *testing.T) {
	t.Parallel()
	srv := serve(t, envoyFront(pythonApp))

	rr := modtest.RequestJSON(t, srv.URL+"/api/items", `{"name":"a"}`)
	res, err := New().ScanPerRequest(rr, modtest.Requester(t), scanCtxFor(srv.URL, ""))
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, srv.URL+"/api/items", res[0].URL)
	assert.Equal(t, "br", res[0].Metadata["encoding"])
	assert.Contains(t, res[0].Metadata["decoder"], "Envoy")
}

// A guard that refuses br but checks only the first token lets "gzip, br"
// through to a decoder that handles both.
func TestScanPerRequest_StackedEncodingBypass(t *testing.T) {
	t.Parallel()
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		enc := r.Header.Get("Content-Encoding")
		if first, _, _ := strings.Cut(enc, ","); first != "" && first != "gzip" {
			http.Error(w, "Use gzip or an uncompressed body", http.StatusUnsupportedMediaType)
			return
		}
		body, ok := decode(raw, enc)
		if !ok {
			http.Error(w, "bad encoding", http.StatusBadRequest)
			return
		}
		handleItems(w, body)
	}))

	rr := modtest.RequestJSON(t, srv.URL+"/api/items", `{"name":"a"}`)
	res, err := New().ScanPerRequest(rr, modtest.Requester(t), scanCtxFor(srv.URL, ""))
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, stackedEncoding, res[0].Metadata["encoding"])
}

func TestScanPerRequest_NoFinding(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		handler http.Handler
	}{
		// body-parser 1.x (Express 4) refuses br like any unknown encoding.
		{"node without brotli", nodeApp(false, true)},
		// Brotli bytes reach the JSON parser undecoded and are malformed.
		{"server ignores Content-Encoding", pythonApp},
		// Any encoded body is dropped and read as {}: the unknown-encoding
		// control is answered like the br probe.
		{"server drops encoded bodies", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			if r.Header.Get("Content-Encoding") != "" {
				raw = []byte("{}")
			}
			handleItems(w, raw)
		})},
		// The route answers the same whatever the body: no signal.
		{"body-insensitive route", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			_, _ = w.Write([]byte("ok"))
		})},
		// An edge refuses unknown encodings but passes br untouched to an app
		// that never reads the body: br is answered like {}, the control is
		// not, and only the malformed-JSON check shows there is no signal.
		{"edge refuses unknown encodings, app ignores body", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			if enc := r.Header.Get("Content-Encoding"); enc != "" && enc != "br" && enc != "gzip" {
				http.Error(w, "unsupported encoding", http.StatusUnsupportedMediaType)
				return
			}
			_, _ = w.Write([]byte("ok"))
		})},
		// The header, not the content, drives the answer: br bodies are
		// dropped and read as {}, unknown encodings get a 415 with odd
		// headers. Encoded {} matches plain {} and the control differs, but
		// encoded { is answered like {} rather than like plain {.
		{"br answer driven by the header", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			switch r.Header.Get("Content-Encoding") {
			case "":
			case "br", stackedEncoding:
				raw = []byte("{}")
			default:
				w.Header().Set("X-Edge-Reject", "encoding")
				http.Error(w, "unsupported", http.StatusUnsupportedMediaType)
				return
			}
			handleItems(w, raw)
		})},
		// Any odd header gets the same error as an odd Content-Encoding: the
		// unknown-encoding control differing says nothing about
		// Content-Encoding, so a real decoder behind it is not reported.
		{"odd headers alone move the answer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(decoyHeader) != "" {
				http.Error(w, "Bad Request: unexpected header", http.StatusBadRequest)
				return
			}
			envoyFront(pythonApp).ServeHTTP(w, r)
		})},
		// Decodes whenever any header names a coding it knows, and ignores
		// a header value it does not (so the random decoy is answered like
		// plain {}): nothing ties the answer to Content-Encoding.
		{"decodes on any header naming br", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			if enc := r.Header.Get("Content-Encoding"); enc != "" {
				body, ok := decode(raw, enc)
				if !ok {
					http.Error(w, "unsupported", http.StatusUnsupportedMediaType)
					return
				}
				raw = body
			} else if body, ok := decode(raw, r.Header.Get(decoyHeader)); ok {
				raw = body
			}
			handleItems(w, raw)
		})},
		// The baseline errors: a 5xx answers every probe alike and anchors
		// nothing, even behind a real decoder.
		{"5xx baseline", envoyFront(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			if string(raw) == "{}" {
				http.Error(w, "upstream error", http.StatusBadGateway)
				return
			}
			handleItems(w, raw)
		}))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := serve(t, tc.handler)
			client := modtest.Requester(t)
			sc := scanCtxFor(srv.URL, "express")
			res, err := New().ScanPerHost(modtest.Request(t, srv.URL+"/"), client, sc)
			require.NoError(t, err)
			assert.Empty(t, res, "host lane")
			for _, path := range []string{"/upload", "/api/items"} {
				res, err := New().ScanPerRequest(modtest.RequestJSON(t, srv.URL+path, `{"name":"a"}`), client, sc)
				require.NoError(t, err)
				assert.Empty(t, res, path)
			}
		})
	}
}

// A pool where only some backends decode br passes the first round and
// breaks on the repeat: the second encoded {} lands on a backend that parses
// the raw bytes.
func TestScanPerRequest_FlakyDecoderNotReported(t *testing.T) {
	t.Parallel()
	var brSeen int64
	decoding := envoyFront(pythonApp)
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") == "br" && atomic.AddInt64(&brSeen, 1) > 2 {
			pythonApp.ServeHTTP(w, r)
			return
		}
		decoding.ServeHTTP(w, r)
	}))

	rr := modtest.RequestJSON(t, srv.URL+"/api/items", `{"name":"a"}`)
	res, err := New().ScanPerRequest(rr, modtest.Requester(t), scanCtxFor(srv.URL, ""))
	require.NoError(t, err)
	assert.Empty(t, res)
	assert.EqualValues(t, 3, atomic.LoadInt64(&brSeen), "the repeat round sent the third br probe")
}

func TestCarriesJSONBody(t *testing.T) {
	t.Parallel()
	assert.True(t, carriesJSONBody("POST", "application/json; charset=utf-8"))
	assert.True(t, carriesJSONBody("PATCH", "application/vnd.api+json"))
	assert.False(t, carriesJSONBody("PUT", "application/json"), "PUT {} can replace a resource")
	assert.False(t, carriesJSONBody("GET", "application/json"))
	assert.False(t, carriesJSONBody("POST", "application/x-www-form-urlencoded"))
	assert.False(t, carriesJSONBody("POST", ""))
}

// The precomputed probe streams decode back to {} and {: the oracle depends on it.
func TestEncodedProbesRoundTrip(t *testing.T) {
	t.Parallel()
	for _, e := range encodings {
		out, ok := decode(e.empty, e.encoding)
		require.True(t, ok, e.encoding)
		assert.Equal(t, emptyBody, out, e.encoding)
		out, ok = decode(e.malformed, e.encoding)
		require.True(t, ok, e.encoding)
		assert.Equal(t, malformedBody, out, e.encoding)
	}
}
