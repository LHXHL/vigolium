package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// --knowledge-base isn't just prose. When a file in the KB is an HTTP-traffic
// export — a HAR capture, a Burp XML session, a curl script, an OpenAPI /
// Swagger spec, a Postman collection, a URL list, or a raw HTTP request — it is
// parsed into real http_records and ingested into the project DB exactly like a
// `vigolium ingest` / Burp import (source="knowledge-base"), then a bounded
// sample is folded into the operator's opening brief. The prose docs
// (markdown/txt/rst/…) still flow through the distill/index path in
// agent_autopilot_knowledge_base.go; this file owns the traffic half. The two
// are routed by content so a single --knowledge-base directory can mix docs and
// captures. --knowledge-base-no-traffic disables this and treats every file as
// prose.

const (
	// kbTrafficSource labels http_records parsed out of the knowledge base.
	// Distinct from "burp"/"scanner" so priorSourceBreakdown surfaces them and
	// the operator can `query_records --source knowledge-base`.
	kbTrafficSource = "knowledge-base"

	// kbTrafficMaxRecordsPerFile caps how many records a single capture can
	// contribute, so a giant HAR can't blow up ingestion. The rest of the file
	// is simply not parsed (the sample line notes when a file was capped).
	kbTrafficMaxRecordsPerFile = 2000

	// kbTrafficSampleCap bounds the endpoint sample inlined into the brief;
	// everything ingested stays queryable via query_records regardless.
	kbTrafficSampleCap = 15
)

// kbTrafficFile is one knowledge-base file recognized as an HTTP-traffic export.
type kbTrafficFile struct {
	AbsPath string // absolute path fed to the format parser
	RelPath string // path relative to the KB root (basename for a single file)
	Format  string // canonical format name understood by source.ParseFileRecords
}

// kbTrafficFormat classifies a file as an HTTP-traffic export and returns the
// canonical format name to parse it with, or ("", false) when the file is not
// traffic (a prose doc, an unknown blob, unreadable). The format comes from
// source.DetectFormatHead, the one content detector (so a capture with a
// misleading or missing extension is still recognized). The URL-list fallback
// is held to a stricter bar here so a prose .txt/.md is never misread as
// traffic: only .urls/.txt/.list files whose every line is an http(s) URL.
func kbTrafficFormat(absPath string) (string, bool) {
	head := readFileHead(absPath, source.DetectHeadBytes)
	if len(head) == 0 || looksBinaryBytes(head) {
		return "", false
	}
	det := source.DetectFormatHead(head, filepath.Base(absPath))
	switch {
	case det.Detected() && det.Format == "curl" && det.Score < 90 && kbTextExtensions[strings.ToLower(filepath.Ext(absPath))]:
		// A prose doc that merely contains curl examples (the sniffer's weak
		// "script/markdown containing curl" signal) stays prose; only a doc
		// that starts as a curl command is traffic.
		return "", false
	case det.Detected():
		return det.Format, true
	case det.Format == "urls":
		switch strings.ToLower(filepath.Ext(absPath)) {
		case ".urls", ".txt", ".list":
			if looksLikeURLList(string(head)) {
				return "urls", true
			}
		}
	}
	return "", false
}

// looksLikeURLList reports whether every non-blank line in head is an http(s)
// URL (and there is at least one). Used only for .urls/.list files or content
// with no other signature, so a prose .txt is never treated as a URL list.
func looksLikeURLList(head string) bool {
	seen := false
	for _, ln := range strings.Split(head, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if !strings.HasPrefix(ln, "http://") && !strings.HasPrefix(ln, "https://") {
			return false
		}
		seen = true
	}
	return seen
}

// readFileHead reads up to n bytes from the start of a file, returning nil on
// any error (unreadable → not traffic).
func readFileHead(absPath string, n int) []byte {
	f, err := os.Open(absPath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, n)
	read, err := io.ReadFull(f, buf)
	if read == 0 && err != nil {
		return nil
	}
	return buf[:read]
}

// gatherKnowledgeBaseTrafficFiles walks a knowledge-base path (single file or
// directory tree) and returns the files recognized as HTTP-traffic exports, in
// a stable relpath-sorted order. Shares the KB walk's skip-dirs and file cap so
// it stays bounded and consistent with the prose gatherer.
func gatherKnowledgeBaseTrafficFiles(kbPath string) (rootAbs string, files []kbTrafficFile, err error) {
	rootAbs, err = filepath.Abs(kbPath)
	if err != nil {
		return "", nil, err
	}
	info, err := os.Stat(rootAbs)
	if err != nil {
		return "", nil, err
	}

	if !info.IsDir() {
		if fmtName, ok := kbTrafficFormat(rootAbs); ok {
			files = append(files, kbTrafficFile{AbsPath: rootAbs, RelPath: filepath.Base(rootAbs), Format: fmtName})
		}
		return rootAbs, files, nil
	}

	walkErr := filepath.WalkDir(rootAbs, func(path string, d os.DirEntry, we error) error {
		if we != nil {
			return nil
		}
		if d.IsDir() {
			if path != rootAbs && kbSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if len(files) >= kbMaxFiles {
			return nil
		}
		if fmtName, ok := kbTrafficFormat(path); ok {
			rel, relErr := filepath.Rel(rootAbs, path)
			if relErr != nil {
				rel = filepath.Base(path)
			}
			files = append(files, kbTrafficFile{AbsPath: path, RelPath: filepath.ToSlash(rel), Format: fmtName})
		}
		return nil
	})
	if walkErr != nil {
		return rootAbs, nil, walkErr
	}
	sort.Slice(files, func(i, j int) bool { return files[i].RelPath < files[j].RelPath })
	return rootAbs, files, nil
}

// ingestKnowledgeBaseTraffic parses every HTTP-traffic-format file under the
// knowledge base into HTTP records, ingests them into the project DB as normal
// traffic (source="knowledge-base", then de-duplicated by that source), and
// returns a compact markdown section — an actionable endpoint sample — to fold
// into the operator's opening brief plus the number of records saved. Returns
// ("", 0) when the KB holds no traffic files, nothing parsed, or ingestion
// failed; every failure is non-fatal (logged to w) so the autopilot run
// continues on the prose brief alone. repo must be non-nil (the caller gates on
// it — records need somewhere to land).
func ingestKnowledgeBaseTraffic(ctx context.Context, repo *database.Repository, projectUUID, kbPath string, w io.Writer) (section string, saved int) {
	if repo == nil {
		return "", 0
	}
	rootAbs, files, err := gatherKnowledgeBaseTrafficFiles(kbPath)
	if err != nil || len(files) == 0 {
		return "", 0
	}

	var records []*httpmsg.HttpRequestResponse
	parsed := make([]string, 0, len(files))
	for _, tf := range files {
		recs, perr := source.ParseFileRecords(tf.AbsPath, tf.Format, kbTrafficMaxRecordsPerFile)
		if perr != nil && len(recs) == 0 {
			_, _ = fmt.Fprintf(w, "%s Knowledge base: skipped %s (%s): %v\n",
				terminal.WarningSymbol(), tf.RelPath, tf.Format, perr)
			continue
		}
		if len(recs) == 0 {
			continue
		}
		records = append(records, recs...)
		parsed = append(parsed, fmt.Sprintf("`%s` (%s, %d)", tf.RelPath, tf.Format, len(recs)))
	}
	if len(records) == 0 {
		return "", 0
	}

	uuids, serr := repo.SaveRecordBatch(ctx, records, kbTrafficSource, projectUUID)
	if serr != nil {
		_, _ = fmt.Fprintf(w, "%s Knowledge base: failed to ingest parsed traffic: %v — continuing without it\n",
			terminal.WarningSymbol(), serr)
		return "", 0
	}
	saved = database.CountSaved(uuids)
	// Collapse exact duplicates within the knowledge-base source (idempotent
	// across --resume re-ingests). Best-effort — a dedup error doesn't lose the
	// records, it just leaves duplicates.
	if _, derr := repo.DeduplicateRecordsBySource(ctx, projectUUID, kbTrafficSource); derr != nil {
		zap.L().Debug("knowledge-base traffic dedup failed", zap.Error(derr))
	}

	_, _ = fmt.Fprintf(w, "%s Knowledge base: parsed %d request(s) from %d traffic file(s) under %s → ingested as normal traffic (source=%s)\n",
		terminal.SuccessSymbol(), len(records), len(parsed), terminal.ShortenHome(rootAbs), kbTrafficSource)

	return renderKnowledgeBaseTrafficSection(ctx, repo, projectUUID, parsed, len(records)), saved
}

// renderKnowledgeBaseTrafficSection builds the markdown block folded into the
// operator's brief: a directive that these are real, already-observed endpoints
// to mine (not re-derive), the parsed-file provenance, and a bounded sample
// endpoint table pulled back from the DB (post-dedup, deterministic order).
func renderKnowledgeBaseTrafficSection(ctx context.Context, repo *database.Repository, projectUUID string, parsedFiles []string, total int) string {
	var b strings.Builder
	b.WriteString("## Seed traffic from knowledge base\n\n")
	fmt.Fprintf(&b, "The knowledge base included HTTP-traffic exports. Their %d request(s) were parsed and "+
		"ingested into the project DB as **normal traffic** (`source=%s`) — treat them as real, already-observed "+
		"endpoints: query them with `query_records --source %s`, then replay and vary them rather than re-deriving "+
		"the attack surface from scratch.\n\n", total, kbTrafficSource, kbTrafficSource)
	if len(parsedFiles) > 0 {
		b.WriteString("Parsed files: " + strings.Join(parsedFiles, ", ") + "\n\n")
	}
	if sample := sampleKBTrafficRecords(ctx, repo, projectUUID, kbTrafficSampleCap); sample != "" {
		b.WriteString(sample)
	}
	return strings.TrimRight(b.String(), "\n")
}

// sampleKBTrafficRecords returns a compact markdown table of up to limit
// knowledge-base endpoints (deduped by method+path), so the operator sees the
// seeded surface without an extra tool call. Returns "" on any query error or
// when nothing matched.
func sampleKBTrafficRecords(ctx context.Context, repo *database.Repository, projectUUID string, limit int) string {
	if repo == nil || limit <= 0 {
		return ""
	}
	var rows []struct {
		Method string `bun:"method"`
		URL    string `bun:"url"`
		Status int    `bun:"status"`
	}
	err := repo.DB().NewSelect().
		Table("http_records").
		ColumnExpr("method").
		ColumnExpr("MAX(url) AS url").
		ColumnExpr("MAX(status_code) AS status").
		Where("project_uuid = ?", projectUUID).
		Where("source = ?", kbTrafficSource).
		GroupExpr("method, path").
		OrderExpr("MAX(status_code) DESC, method ASC").
		Limit(int64(limit)).
		Scan(ctx, &rows)
	if err != nil || len(rows) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "**Sample endpoints (%d, deduped by method+path):**\n\n", len(rows))
	b.WriteString("| Method | Status | URL |\n")
	b.WriteString("|---|---|---|\n")
	for _, r := range rows {
		status := ""
		if r.Status > 0 {
			status = fmt.Sprintf("%d", r.Status)
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", r.Method, status, truncateLine(r.URL, 100))
	}
	return strings.TrimRight(b.String(), "\n")
}
