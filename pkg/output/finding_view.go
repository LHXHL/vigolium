package output

import (
	"encoding/json"
	"net/url"
	"strings"
	"time"
)

// FindingView is one finding as the tabular renderers (csv, junit, github)
// read it: the scalar fields of the finding view `vigolium finding -j` prints
// (pkg/cli compactFindingView), under the same JSON keys. It decodes a stored
// finding row (database.Finding, the export envelope's data) and a rendered
// finding view alike, so a column or key in these reports means exactly what
// the same key means in `finding -j` and the scan document's items. The
// nuclei-shaped output.ResultEvent keys (template-id, matched-at, info{}) are
// never read here.
//
// pkg/database imports this package, so the stored model cannot be named
// directly; a pkg/cli test keeps these keys a subset of compactFindingView's.
type FindingView struct {
	ID              int64    `json:"id"`
	FindingHash     string   `json:"finding_hash"`
	Severity        string   `json:"severity"`
	Confidence      string   `json:"confidence"`
	ModuleID        string   `json:"module_id"`
	ModuleName      string   `json:"module_name"`
	Short           string   `json:"short"`
	URL             string   `json:"url"`
	Hostname        string   `json:"hostname"`
	MatchedAt       []string `json:"matched_at"`
	ScanUUID        string   `json:"scan_uuid"`
	HTTPRecordUUIDs []string `json:"http_record_uuids"`
	Status          string   `json:"status"`
	CWEID           string   `json:"cwe_id"`
	SourceFile      string   `json:"source_file"`
	RepoName        string   `json:"repo_name"`
	FoundAt         string   `json:"found_at"`
}

// decodeFindingView reads one finding envelope's data. The stored row names
// the short description module_short; the finding view names it short.
// found_at is normalized to RFC 3339 seconds, as the finding view prints it,
// and a zero time reads as unset.
func decodeFindingView(data json.RawMessage) FindingView {
	var raw struct {
		FindingView
		ModuleShort string `json:"module_short"`
	}
	// best-effort: render whatever fields decode; a malformed finding yields a sparse row.
	_ = json.Unmarshal(data, &raw)
	v := raw.FindingView
	if v.Short == "" {
		v.Short = raw.ModuleShort
	}
	v.Severity = strings.ToLower(v.Severity)
	if ts, err := time.Parse(time.RFC3339Nano, v.FoundAt); err == nil {
		v.FoundAt = ""
		if !ts.IsZero() {
			v.FoundAt = ts.Format(time.RFC3339)
		}
	}
	return v
}

// collectFindingViews decodes the finding envelopes of an export item set in
// item order.
func collectFindingViews(items []any) []FindingView {
	var out []FindingView
	for _, item := range items {
		raw, err := json.Marshal(item)
		if err != nil {
			continue
		}
		var envelope struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil || envelope.Type != "finding" {
			continue
		}
		out = append(out, decodeFindingView(envelope.Data))
	}
	return out
}

// Name is the finding's display name: the module's short description when it
// has one (it reads as a sentence), else the module name.
func (v FindingView) Name() string {
	if v.Short != "" {
		return v.Short
	}
	return v.ModuleName
}

// Location is where the finding points: its URL, else its source file.
func (v FindingView) Location() string {
	if v.URL != "" {
		return v.URL
	}
	return v.SourceFile
}

// GroupHost is the host a report groups the finding under: the stored
// hostname, else the URL's host, else the repository of a code finding.
func (v FindingView) GroupHost() string {
	if v.Hostname != "" {
		return v.Hostname
	}
	if u, err := url.Parse(v.URL); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return v.RepoName
}
