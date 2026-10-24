package fingerprint

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/html"
)

// Samples and signatures built from stored responses rather than a live
// ResponseChain, so a host's not-found baseline can be learned from the
// responses a scan already stored and compared against any record later.

// NewSampleFromParts builds a sample from one response's parts, the way
// NewSampleFromRC does from a chain: the body is normalized against the
// request URL (a soft-404 page that echoes the requested path hashes the same
// for every path) and HTML is parsed for the HTML-derived attributes.
func NewSampleFromParts(reqURL *url.URL, status int, header http.Header, body []byte) *Sample {
	if header == nil {
		header = http.Header{}
	}
	resp := &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(nil))}
	if reqURL != nil {
		resp.Request = &http.Request{URL: reqURL}
		if len(body) > 0 {
			body = NormalizeBody(body, reqURL)
		}
	}
	var parsed *html.HTMLParsed
	if len(body) > 0 && strings.Contains(strings.ToLower(header.Get("Content-Type")), "html") {
		if hp, err := html.NewParser().Parse(bytes.NewReader(body)); err == nil {
			parsed = hp
		}
	}
	s, _ := newSampleInternal(resp, parsed, body)
	return s
}

// NamedStable returns the signature's stable attributes keyed by attribute
// name, the form a store keeps.
func (sig *Signature) NamedStable() map[string]uint32 {
	out := make(map[string]uint32, len(sig.stable))
	for attr, h := range sig.stable {
		out[attr.String()] = h
	}
	return out
}

// SignatureFromNamed rebuilds a signature from NamedStable's form. Names this
// build does not know are skipped.
func SignatureFromNamed(named map[string]uint32) *Signature {
	sig := &Signature{stable: make(map[Attribute]uint32, len(named)), debug: "stored"}
	for name, h := range named {
		if attr, ok := attributeByName[name]; ok {
			sig.stable[attr] = h
		}
	}
	return sig
}

// attributeByName indexes AttributeRegistry by name, for SignatureFromNamed.
var attributeByName = func() map[string]Attribute {
	m := make(map[string]Attribute, len(AttributeRegistry))
	for attr, meta := range AttributeRegistry {
		m[meta.Name] = attr
	}
	return m
}()
