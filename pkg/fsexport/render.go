// Package fsexport renders HTTP records and findings into a flat, browsable
// filesystem tree (the `fs` output format and the server's --mirror-fs live
// mirror). It holds the shared layout rules so the one-shot CLI exporter
// (pkg/cli) and the live server mirror stay byte-for-byte consistent:
//
//	<root>/traffic/<host>/<id>.req           # "@target <scheme>://<host>" + raw request
//	<root>/traffic/<host>/<id>.resp.headers  # status line + response headers
//	<root>/traffic/<host>/<id>.resp.body     # response body, gzip-decoded
//	<root>/findings/<host>/<id>.md           # finding, with the request/response
//	                                         # embedded inline and cross-linked to its .req
//
// The package depends only on the database record/finding models, so it is
// importable from both the CLI and the server without an import cycle.
package fsexport

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
)

// TrafficEntry is one row of a traffic index. `Path` is the ready-to-open prefix
// within the traffic dir — append .req / .resp.headers / .resp.body. `Finding`,
// when non-nil, is the highest severity of any finding that references this
// record (populated only by the one-shot exporter; the live mirror leaves it
// nil since findings arrive after the record is written).
type TrafficEntry struct {
	ID          string  `json:"id"`
	Host        string  `json:"host"`
	Path        string  `json:"path"`
	Method      string  `json:"method"`
	URL         string  `json:"url"`
	Status      int     `json:"status"`
	ContentType string  `json:"content_type,omitempty"`
	Bytes       int64   `json:"bytes"`
	Finding     *string `json:"finding"`
}

// InlineBodyCap bounds how many bytes of a linked response body are embedded
// inline in a finding markdown. The full body always remains in the linked
// .resp.body file, so this only trims the self-contained inline copy.
const InlineBodyCap = 32 * 1024

// LinkedRecord is the resolved on-disk content of one traffic record a finding
// links to. It carries both the link `Path` (for the cross-link section) and the
// raw request/response, so the finding markdown can embed the traffic inline and
// stay self-contained — readable or shareable without opening the linked files.
type LinkedRecord struct {
	Path          string // "host/id" link prefix under the traffic dir
	Request       string // raw request, with the synthetic @target marker line stripped
	ResponseHead  string // status line + response headers (includes the blank-line separator)
	ResponseBody  string // decoded response body, capped to InlineBodyCap
	BodyTruncated bool   // true when ResponseBody was capped
}

// FindingEntry is one row of a findings index. `Path` is the markdown file
// within the findings dir; `Traffic` lists the traffic `Path` prefixes this
// finding is linked to.
type FindingEntry struct {
	ID         string   `json:"id"`
	Host       string   `json:"host"`
	Path       string   `json:"path"`
	Severity   string   `json:"severity"`
	Confidence string   `json:"confidence"`
	Module     string   `json:"module"`
	Title      string   `json:"title"`
	URL        string   `json:"url,omitempty"`
	Traffic    []string `json:"traffic"`
}

// TargetLine builds the "@target <scheme>://<authority>" header line prepended
// to a .req file. The port is included only when non-default for the scheme, so
// the common case reads "@target https://host".
func TargetLine(rec *database.HTTPRecord) string {
	scheme := rec.Scheme
	if scheme == "" {
		scheme = "http"
	}
	authority := rec.Hostname
	switch {
	case rec.Port == 0:
	case scheme == "https" && rec.Port != 443:
		authority = fmt.Sprintf("%s:%d", rec.Hostname, rec.Port)
	case scheme == "http" && rec.Port != 80:
		authority = fmt.Sprintf("%s:%d", rec.Hostname, rec.Port)
	}
	return "@target " + scheme + "://" + authority
}

// RequestBytes returns the bytes written to a record's .req file: the
// "@target <scheme>://<host>" line then the raw request verbatim.
func RequestBytes(rec *database.HTTPRecord) []byte {
	return append([]byte(TargetLine(rec)+"\n"), rec.RawRequest...)
}

// WriteResponseFiles writes <dir>/<id>.resp.headers and <id>.resp.body for rec
// (body gzip-decoded so it greps clean), unless omitResponse. The response is
// parsed once. It returns the status code and the number of body bytes written,
// for the index entry. A write error is returned alongside the status already
// determined, so the caller can decide to abort (the one-shot export) or log and
// continue (the live mirror). Shared by both writers so their on-disk shape and
// status/body logic can't drift.
func WriteResponseFiles(dir, id string, rec *database.HTTPRecord, omitResponse bool) (status int, bodyLen int64, err error) {
	return WriteResponseFilesMode(dir, id, rec, omitResponse, 0o644)
}

// WriteResponseFilesMode is WriteResponseFiles with the file mode named: the
// one-shot export keeps 0644, the live mirror writes owner-only. Each file is
// written atomically (temp + rename), so a crash never leaves a truncated one.
func WriteResponseFilesMode(dir, id string, rec *database.HTTPRecord, omitResponse bool, perm os.FileMode) (status int, bodyLen int64, err error) {
	if !omitResponse {
		if resp := rec.ParsedResponse(); resp != nil {
			status = resp.StatusCode()
			if head := resp.Head(); len(head) > 0 {
				if err = writeFileAtomic(filepath.Join(dir, id+".resp.headers"), head, perm); err != nil {
					return status, 0, err
				}
			}
			if body := DecodeBody(resp.Body()); len(body) > 0 {
				if err = writeFileAtomic(filepath.Join(dir, id+".resp.body"), body, perm); err != nil {
					return status, 0, err
				}
				bodyLen = int64(len(body))
			}
			return status, bodyLen, nil
		}
	}
	if rec.HasResponse {
		status = rec.StatusCode
	}
	return status, 0, nil
}

// ReadLinkedRecord loads the .req/.resp.headers/.resp.body files previously
// written under trafficRoot for relPath ("host/id"), so a finding can embed that
// traffic inline. Missing or unreadable files yield empty fields (the renderer
// then embeds whatever is present). The request's leading "@target" marker line
// is stripped so the embedded request is a clean raw HTTP request, and the body
// is capped to InlineBodyCap. When omitResponse is set the response files were
// never written, so only the request is loaded.
func ReadLinkedRecord(trafficRoot, relPath string, omitResponse bool) LinkedRecord {
	lr := LinkedRecord{Path: relPath}
	base := filepath.Join(trafficRoot, filepath.FromSlash(relPath))
	if data, err := os.ReadFile(base + ".req"); err == nil {
		lr.Request = stripTargetLine(string(data))
	}
	if omitResponse {
		return lr
	}
	if data, err := os.ReadFile(base + ".resp.headers"); err == nil {
		lr.ResponseHead = string(data)
	}
	if data, err := os.ReadFile(base + ".resp.body"); err == nil {
		if len(data) > InlineBodyCap {
			data = data[:InlineBodyCap]
			lr.BodyTruncated = true
		}
		lr.ResponseBody = string(data)
	}
	return lr
}

// stripTargetLine removes the leading "@target ..." marker line that RequestBytes
// prepends to a .req file, leaving just the raw HTTP request.
func stripTargetLine(req string) string {
	if !strings.HasPrefix(req, "@target ") {
		return req
	}
	if nl := strings.IndexByte(req, '\n'); nl >= 0 {
		return req[nl+1:]
	}
	return ""
}

// DecodeBody gzip-decodes a response body so it greps cleanly on disk. Bodies
// that aren't gzip (the common case) are returned unchanged, including binary
// payloads — the index's content_type lets an agent skip those.
func DecodeBody(body []byte) []byte {
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		return body
	}
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return body
	}
	defer func() { _ = zr.Close() }()
	out, err := io.ReadAll(zr)
	if err != nil || len(out) == 0 {
		return body
	}
	return out
}

// CleanContentType trims the parameters (charset, boundary, …) off a response
// content type, keeping just the media type.
func CleanContentType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.TrimSpace(ct)
}

// SanitizeHost makes a hostname safe to use as a directory name, replacing path
// separators and other filesystem-hostile characters. An empty host becomes
// "unknown-host".
func SanitizeHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return "unknown-host"
	}
	return strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|', 0:
			return '_'
		}
		return r
	}, host)
}

// FindingHost returns the host a finding belongs under: its denormalized
// hostname, else the host parsed from its URL, else "unknown-host".
func FindingHost(f *database.Finding) string {
	if f.Hostname != "" {
		return f.Hostname
	}
	if f.URL != "" {
		if u, err := url.Parse(f.URL); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	return "unknown-host"
}

// SeverityRank orders severities so an index can record the single highest
// severity touching a record.
func SeverityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 6
	case "high":
		return 5
	case "medium":
		return 4
	case "low":
		return 3
	case "info", "informational":
		return 2
	case "suspect":
		return 1
	}
	return 0
}

// MaxSeverity returns the higher-ranked of two severity strings.
func MaxSeverity(a, b string) string {
	if SeverityRank(b) > SeverityRank(a) {
		return b
	}
	return a
}

// RenderFindingMarkdown renders a finding as a self-contained markdown file. It
// embeds the raw request and response inline so the finding can be read or shared
// on its own, and — when linked traffic is present — also cross-links the full
// .req/.resp files (relative to the findings dir, via trafficDirBase — e.g.
// "traffic" for the live mirror or "<base>-traffic" for the one-shot export) so
// the complete bodies and any additional records stay reachable. The inline
// request/response prefers the finding's own curated evidence (active modules
// capture the exact attack request) and falls back to the first linked record's
// stored traffic (the usual source for passive findings, which carry none of
// their own).
func RenderFindingMarkdown(f *database.Finding, linked []LinkedRecord, trafficDirBase string) []byte {
	var b strings.Builder
	title := f.ModuleName
	if title == "" {
		title = f.ModuleID
	}
	fmt.Fprintf(&b, "# %s — %s\n\n", strings.ToUpper(OrDash(f.Severity)), title)

	fmt.Fprintf(&b, "- **Module:** `%s`", f.ModuleID)
	if f.ModuleType != "" {
		fmt.Fprintf(&b, " (%s)", f.ModuleType)
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "- **Severity:** %s\n", OrDash(f.Severity))
	fmt.Fprintf(&b, "- **Confidence:** %s\n", OrDash(f.Confidence))
	if f.URL != "" {
		fmt.Fprintf(&b, "- **URL:** %s\n", f.URL)
	}
	if f.CWEID != "" {
		fmt.Fprintf(&b, "- **CWE:** %s\n", f.CWEID)
	}
	if f.CVSSScore > 0 {
		fmt.Fprintf(&b, "- **CVSS:** %.1f\n", f.CVSSScore)
	}
	if !f.FoundAt.IsZero() {
		fmt.Fprintf(&b, "- **Found:** %s\n", f.FoundAt.UTC().Format(time.RFC3339))
	}
	b.WriteString("\n")

	if f.Description != "" {
		b.WriteString("## Description\n\n")
		b.WriteString(f.Description)
		b.WriteString("\n\n")
	}

	if len(f.MatchedAt) > 0 || len(f.ExtractedResults) > 0 || len(f.AdditionalEvidence) > 0 {
		b.WriteString("## Evidence\n\n")
		for _, m := range f.MatchedAt {
			fmt.Fprintf(&b, "- Matched at: %s\n", m)
		}
		for _, e := range f.ExtractedResults {
			fmt.Fprintf(&b, "- Extracted: %s\n", e)
		}
		for _, e := range f.AdditionalEvidence {
			fmt.Fprintf(&b, "- %s\n", e)
		}
		b.WriteString("\n")
	}

	// Inline request/response — keep the finding self-contained. Prefer the
	// finding's own curated evidence; fall back to the first linked record's
	// stored traffic for findings (typically passive) that carry none of their own.
	inlineReq := f.Request
	inlineResp := f.Response
	bodyTruncated := false
	truncPath := ""
	if len(linked) > 0 {
		lr := linked[0]
		if inlineReq == "" {
			inlineReq = lr.Request
		}
		if inlineResp == "" && (lr.ResponseHead != "" || lr.ResponseBody != "") {
			inlineResp = lr.ResponseHead + lr.ResponseBody
			bodyTruncated = lr.BodyTruncated
			truncPath = lr.Path
		}
	}
	if inlineReq != "" {
		b.WriteString("## Request\n\n```http\n")
		b.WriteString(strings.TrimRight(inlineReq, "\r\n"))
		b.WriteString("\n```\n\n")
	}
	if inlineResp != "" {
		b.WriteString("## Response\n\n```http\n")
		b.WriteString(strings.TrimRight(inlineResp, "\r\n"))
		b.WriteString("\n```\n\n")
		if bodyTruncated && truncPath != "" {
			fmt.Fprintf(&b, "_Response body truncated to %d KB inline — full body: [%s.resp.body](../../%s/%s.resp.body)._\n\n",
				InlineBodyCap/1024, truncPath, trafficDirBase, truncPath)
		}
	}

	// Traffic links — the full .req/.resp files (complete bodies and any
	// additional linked records not shown inline above).
	if len(linked) > 0 {
		b.WriteString("## Traffic\n\n")
		for _, lr := range linked {
			link := "../../" + trafficDirBase + "/" + lr.Path
			fmt.Fprintf(&b, "- [request](%s.req) · [response headers](%s.resp.headers) · [response body](%s.resp.body)\n", link, link, link)
		}
		b.WriteString("\n")
	}

	if f.Remediation != "" {
		b.WriteString("## Remediation\n\n")
		b.WriteString(f.Remediation)
		b.WriteString("\n")
	}

	return []byte(b.String())
}

// OrDash returns s, or "-" when s is empty, for tidy markdown metadata lines.
func OrDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
