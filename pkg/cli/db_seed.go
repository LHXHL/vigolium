package cli

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var dbSeedCmd = &cobra.Command{
	Use:   "seed",
	Short: "Populate database with sample data for development and testing",
	Long:  "Insert a curated set of fake hosts, scans, HTTP records, and findings into the active database. Useful for exercising db, traffic, and finding subcommands without running an actual scan.",
	RunE:  runDBSeed,
}

func init() {
	dbCmd.AddCommand(dbSeedCmd)
}

func runDBSeed(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	// Write intent: the opener creates the schema on a new database.
	db, err := getDBFor(clicommon.IntentWrite)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	ctx := context.Background()

	rng := rand.New(rand.NewSource(42)) // deterministic for reproducibility

	// Check if seed data already exists
	var existingCount int64
	existingCount, err = db.NewSelect().Model((*database.Scan)(nil)).Where("uuid LIKE 'scan-000%'").Count(ctx)
	if err == nil && existingCount > 0 && !globalForce {
		return fmt.Errorf("database already contains seed data (%d seed scans found). Use --force to re-insert (duplicates will be skipped)", existingCount)
	}

	// Progress is human text: stdout normally, stderr under -j, where stdout
	// carries the one result document.
	tally := &seedTally{progress: humanOut()}
	_, _ = fmt.Fprintf(tally.progress, "%s Seeding database with sample data...\n\n", terminal.InfoSymbol())

	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	// Use ON CONFLICT DO NOTHING so re-running is idempotent
	// --- Users ---
	users := seedUsers()
	usersInserted := 0
	for _, u := range users {
		res, err := db.NewInsert().Model(u).On("CONFLICT DO NOTHING").Exec(ctx)
		if err != nil {
			return fmt.Errorf("failed to insert user %s: %w", u.UUID, err)
		}
		usersInserted += rowsAffected(res)
	}
	tally.add("users", "users", usersInserted)

	// --- Projects ---
	projects := seedProjects(users)
	projectsInserted := 0
	for _, p := range projects {
		res, err := db.NewInsert().Model(p).On("CONFLICT DO NOTHING").Exec(ctx)
		if err != nil {
			return fmt.Errorf("failed to insert project %s: %w", p.UUID, err)
		}
		projectsInserted += rowsAffected(res)
	}
	tally.add("projects", "projects", projectsInserted)

	// --- Scans ---
	scans := seedScans(rng)
	scansInserted := 0
	for _, s := range scans {
		s.ProjectUUID = projectUUID
		res, err := db.NewInsert().Model(s).On("CONFLICT DO NOTHING").Exec(ctx)
		if err != nil {
			return fmt.Errorf("failed to insert scan %s: %w", s.UUID, err)
		}
		scansInserted += rowsAffected(res)
	}
	tally.add("scans", "scans", scansInserted)

	// --- HTTP Records ---
	records := seedHTTPRecords(rng, scans)
	recordsInserted := 0
	for _, r := range records {
		r.ProjectUUID = projectUUID
		res, err := db.NewInsert().Model(r).On("CONFLICT DO NOTHING").Exec(ctx)
		if err != nil {
			return fmt.Errorf("failed to insert record %s: %w", r.UUID, err)
		}
		recordsInserted += rowsAffected(res)
	}
	tally.add("http_records", "HTTP records", recordsInserted)

	// --- Findings (check by finding_hash to avoid duplicates on re-seed) ---
	findings := seedFindings(rng, records)
	enrichFindings(findings, records)
	findingsInserted := 0
	for _, f := range findings {
		f.ProjectUUID = projectUUID
		exists, _ := db.NewSelect().Model((*database.Finding)(nil)).Where("finding_hash = ?", f.FindingHash).Exists(ctx)
		if exists {
			continue
		}
		if _, err := db.NewInsert().Model(f).Exec(ctx); err != nil {
			return fmt.Errorf("failed to insert finding: %w", err)
		}
		findingsInserted++
	}
	tally.add("findings", "findings", findingsInserted)

	// --- Finding Records (junction table: finding ↔ HTTP record) ---
	findingRecordsInserted := 0
	for _, f := range findings {
		if f.ID == 0 {
			// Look up the finding ID by hash (it was just inserted or already exists)
			var fid int64
			err := db.NewSelect().Model((*database.Finding)(nil)).Column("id").Where("finding_hash = ?", f.FindingHash).Scan(ctx, &fid)
			if err != nil || fid == 0 {
				continue
			}
			f.ID = fid
		}
		for _, recUUID := range f.HTTPRecordUUIDs {
			res, err := db.NewRaw(
				"INSERT INTO finding_records (finding_id, record_uuid) VALUES (?, ?) ON CONFLICT DO NOTHING",
				f.ID, recUUID,
			).Exec(ctx)
			if err != nil {
				continue // skip on error (e.g. FK violation)
			}
			findingRecordsInserted += rowsAffected(res)
		}
	}
	tally.add("finding_records", "finding_records", findingRecordsInserted)

	// --- Scopes (check by name to avoid duplicates on re-seed) ---
	scopes := seedScopes()
	scopesInserted := 0
	for _, s := range scopes {
		s.ProjectUUID = projectUUID
		exists, _ := db.NewSelect().Model((*database.Scope)(nil)).Where("name = ?", s.Name).Exists(ctx)
		if exists {
			continue
		}
		if _, err := db.NewInsert().Model(s).Exec(ctx); err != nil {
			return fmt.Errorf("failed to insert scope %s: %w", s.Name, err)
		}
		scopesInserted++
	}
	tally.add("scopes", "scope rules", scopesInserted)

	// --- OAST Interactions (check by unique_id to avoid duplicates) ---
	interactions := seedOASTInteractions(scans)
	// Link specific OAST rows to their originating finding via ModuleID heuristic.
	// Findings have their IDs populated by the finding_records loop above.
	moduleIDToFinding := make(map[string]int64, len(findings))
	for _, f := range findings {
		if f.ID > 0 {
			// first-wins preserves the earliest finding for each module ID
			if _, ok := moduleIDToFinding[f.ModuleID]; !ok {
				moduleIDToFinding[f.ModuleID] = f.ID
			}
		}
	}
	oastToFinding := map[string]string{
		"seed-oast-http-002": "ssti-expression-eval", // SSTI blind callback → SSTI finding
		"seed-oast-dns-002":  "xxe-generic",          // XXE DNS callback → XXE finding (none seeded, will be 0)
	}
	oastInserted := 0
	for _, oi := range interactions {
		oi.ProjectUUID = projectUUID
		if mod, ok := oastToFinding[oi.UniqueID]; ok {
			if fid, ok := moduleIDToFinding[mod]; ok {
				oi.FindingID = fid
			}
		}
		exists, _ := db.NewSelect().Model((*database.OASTInteraction)(nil)).Where("unique_id = ?", oi.UniqueID).Exists(ctx)
		if exists {
			continue
		}
		if _, err := db.NewInsert().Model(oi).Exec(ctx); err != nil {
			return fmt.Errorf("failed to insert OAST interaction %s: %w", oi.UniqueID, err)
		}
		oastInserted++
	}
	tally.add("oast_interactions", "OAST interactions", oastInserted)

	// --- Scan Logs ---
	scanLogs := seedScanLogs(scans)
	logsInserted := 0
	for _, sl := range scanLogs {
		sl.ProjectUUID = projectUUID
		res, err := db.NewInsert().Model(sl).On("CONFLICT DO NOTHING").Exec(ctx)
		if err != nil {
			return fmt.Errorf("failed to insert scan log: %w", err)
		}
		logsInserted += rowsAffected(res)
	}
	tally.add("scan_logs", "scan logs", logsInserted)

	// --- Agent Runs ---
	agenticScans := seedAgenticScans(scans)
	agenticScansInserted := 0
	for _, ar := range agenticScans {
		ar.ProjectUUID = projectUUID
		exists, _ := db.NewSelect().Model((*database.AgenticScan)(nil)).Where("uuid = ?", ar.UUID).Exists(ctx)
		if exists {
			continue
		}
		if _, err := db.NewInsert().Model(ar).Exec(ctx); err != nil {
			return fmt.Errorf("failed to insert agent run %s: %w", ar.UUID, err)
		}
		agenticScansInserted++
	}
	tally.add("agentic_scans", "agent runs", agenticScansInserted)

	// --- Session Hostnames ---
	sessions := seedAuthenticationHostnames(scans)
	sessionsInserted := 0
	for _, sh := range sessions {
		sh.ProjectUUID = projectUUID
		exists, _ := db.NewSelect().Model((*database.AuthenticationHostname)(nil)).Where("hostname = ? AND session_name = ?", sh.Hostname, sh.SessionName).Exists(ctx)
		if exists {
			continue
		}
		if _, err := db.NewInsert().Model(sh).Exec(ctx); err != nil {
			return fmt.Errorf("failed to insert session hostname %s/%s: %w", sh.Hostname, sh.SessionName, err)
		}
		sessionsInserted++
	}
	tally.add("authentication_hostnames", "session hostnames", sessionsInserted)

	if globalJSON {
		return emitMutation(cmd, "", mutationResult{
			Changed: tally.total > 0,
			Action:  "seed",
			Items:   tally.rows,
			Extra:   map[string]any{"rows_inserted": tally.total},
			Query:   []string{"db", "stats"},
		}, withProjectScope(projectUUID))
	}
	fmt.Printf("\n%s Seed complete! Use 'vigolium db stats' or 'vigolium traffic' to inspect.\n", terminal.SuccessSymbol())
	return nil
}

// seedTableView is one table `db seed -j` wrote to.
type seedTableView struct {
	Table string `json:"table"`
	// Inserted counts the rows this run added; a row already present (a
	// re-seed under --force) is skipped and not counted.
	Inserted int `json:"inserted"`
}

// seedTally collects the per-table counts and prints the progress lines.
type seedTally struct {
	progress io.Writer
	rows     []seedTableView
	total    int
}

func (t *seedTally) add(table, label string, n int) {
	t.rows = append(t.rows, seedTableView{Table: table, Inserted: n})
	t.total += n
	_, _ = fmt.Fprintf(t.progress, "  %s Inserted %d %s\n", terminal.SuccessSymbol(), n, label)
}

// rowsAffected reads an INSERT … ON CONFLICT DO NOTHING result: 0 when the row
// already existed. A driver that cannot say counts the row as written.
func rowsAffected(res sql.Result) int {
	if res == nil {
		return 0
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 1
	}
	return int(n)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func ptrTime(t time.Time) *time.Time {
	return &t
}

func hasAuthHeader(headers map[string][]string) bool {
	for name := range headers {
		lower := strings.ToLower(name)
		if lower == "authorization" || lower == "cookie" || lower == "x-api-key" {
			return true
		}
	}
	return false
}

// computeRiskScore maps remarks and status to a 0–100 risk hint for sorting.
func computeRiskScore(remarks []string, status int) int {
	score := 0
	for _, r := range remarks {
		switch {
		case strings.HasPrefix(r, "sqli"):
			score += 40
		case strings.HasPrefix(r, "xss"):
			score += 30
		case strings.HasPrefix(r, "lfi"):
			score += 35
		case strings.HasPrefix(r, "open-redirect"):
			score += 15
		case strings.Contains(r, "forbidden-bypass"), strings.Contains(r, "admin"):
			score += 20
		case strings.Contains(r, "data-leak"):
			score += 25
		default:
			score += 5
		}
	}
	if status == 500 {
		score += 10
	}
	if score > 100 {
		score = 100
	}
	return score
}

func buildRawRequest(method, path, hostname string, port int, scheme string, headers map[string][]string, body []byte) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, path)

	hostVal := hostname
	if (scheme == "https" && port != 443) || (scheme == "http" && port != 80) {
		hostVal = fmt.Sprintf("%s:%d", hostname, port)
	}

	// Write Host header first, then the rest
	fmt.Fprintf(&b, "Host: %s\r\n", hostVal)
	for k, vals := range headers {
		if strings.EqualFold(k, "Host") {
			continue
		}
		for _, v := range vals {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	if len(body) > 0 {
		b.Write(body)
	}
	return []byte(b.String())
}

func buildRawResponse(status int, phrase string, headers map[string][]string, contentType string, body []byte) []byte {
	if status == 0 {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, phrase)
	for k, vals := range headers {
		for _, v := range vals {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	if len(body) > 0 {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	if len(body) > 0 {
		b.Write(body)
	}
	return []byte(b.String())
}

func hashStr(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:16]) // 32 hex chars
}
