// Package multipartform renders multipart/form-data bodies for the input
// formats that rebuild a form from a structured description (curl -F, HAR
// postData.params, Postman formdata).
package multipartform

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/textproto"
	"strings"
)

// Part is one form field. A part with a FileName is a file upload; its
// Content-Type defaults to application/octet-stream.
type Part struct {
	Name        string
	FileName    string
	ContentType string
	Value       string
}

// Build renders parts under boundary and returns the body with the matching
// Content-Type (boundary included). mime/multipart does the framing; the
// Content-Disposition parameters are quoted with QuoteParam.
func Build(parts []Part, boundary string) (body, contentType string, err error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.SetBoundary(boundary); err != nil {
		return "", "", err
	}
	for _, p := range parts {
		h := make(textproto.MIMEHeader)
		disposition := "form-data; name=" + QuoteParam(p.Name)
		if p.FileName != "" {
			disposition += "; filename=" + QuoteParam(p.FileName)
		}
		h.Set("Content-Disposition", disposition)
		ct := p.ContentType
		if ct == "" && p.FileName != "" {
			ct = "application/octet-stream"
		}
		if ct != "" {
			h.Set("Content-Type", ct)
		}
		part, err := w.CreatePart(h)
		if err != nil {
			return "", "", err
		}
		if _, err := io.WriteString(part, p.Value); err != nil {
			return "", "", err
		}
	}
	if err := w.Close(); err != nil {
		return "", "", err
	}
	return buf.String(), w.FormDataContentType(), nil
}

// QuoteParam quotes a multipart parameter per RFC 2183 (backslash-escaping
// only quotes and backslashes), which is not the same as Go's %q. CR and LF,
// which would break the header line, become spaces.
func QuoteParam(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\r', '\n':
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
