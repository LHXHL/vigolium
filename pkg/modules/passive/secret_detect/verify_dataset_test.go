package secret_detect

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/secretscan"
)

// TestVerifyDataset re-runs the (fixed) secret-detect module over every stored
// HTTP response in a corpus of scan sqlite DBs, so we can confirm the value-shape
// guard suppresses the Aura-property-path / field-name FP class across real data
// without dropping genuine leaks. Gated on VIG_VERIFY_GLOB so it never runs in CI.
//
//	VIG_VERIFY_GLOB='/path/to/roc*.sqlite' go test -run TestVerifyDataset \
//	    -timeout 30m -v ./pkg/modules/passive/secret_detect/
func TestVerifyDataset(t *testing.T) {
	glob := os.Getenv("VIG_VERIFY_GLOB")
	if glob == "" {
		t.Skip("set VIG_VERIFY_GLOB to a sqlite glob to run the corpus verification")
	}
	dbs, err := filepath.Glob(glob)
	if err != nil || len(dbs) == 0 {
		t.Fatalf("glob %q matched no files (err=%v)", glob, err)
	}

	det, err := secretscan.Default()
	if err != nil {
		t.Fatalf("build detector: %v", err)
	}
	m := New()

	// Surviving findings the fixed module reports (rule -> value -> sample url).
	type kv struct{ rule, val string }
	surviving := map[kv]int{}
	survivingURL := map[kv]string{}
	// Matches my two new predicates now drop (generic-credential family only).
	dottedDrops := map[string]int{}
	keywordDrops := map[string]int{}
	// Any surviving value that STILL looks like the Aura FP shape — must be zero.
	var leakedShapes []string

	var records, dbsOK int
	for _, dbPath := range dbs {
		db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
		if err != nil {
			t.Logf("open %s: %v", dbPath, err)
			continue
		}
		rows, err := db.Query(`SELECT raw_request, raw_response FROM http_records WHERE raw_response IS NOT NULL`)
		if err != nil {
			_ = db.Close()
			continue
		}
		dbsOK++
		for rows.Next() {
			var rawReq, rawResp []byte
			if err := rows.Scan(&rawReq, &rawResp); err != nil {
				continue
			}
			records++

			resp := httpmsg.NewHttpResponse(rawResp)
			if resp == nil {
				continue
			}
			var req *httpmsg.HttpRequest
			if len(rawReq) > 0 {
				req = httpmsg.NewHttpRequest(rawReq)
			} else {
				req = httpmsg.NewHttpRequest([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
			}
			ctx := httpmsg.NewHttpRequestResponse(req, resp)

			// Gate exactly as the executor does in production: CanProcess applies the
			// ShouldScanBody eligibility policy (non-empty, size cap, not media, TEXT
			// MIME). Skipping it here would scan binary bodies (a Blazor .wasm, a
			// font) the real pipeline never feeds the detector — inflating survivors
			// with artifacts. ScanPerRequest itself does not re-gate.
			if !m.CanProcess(ctx) {
				continue
			}

			// 1) Faithful: what the fixed module actually reports.
			findings, _ := m.ScanPerRequest(ctx, nil)
			for _, f := range findings {
				rule, _ := f.Metadata["rule_name"].(string)
				ruleID, _ := f.Metadata["rule_id"].(string)
				for _, v := range f.ExtractedResults {
					k := kv{rule, v}
					surviving[k]++
					if survivingURL[k] == "" {
						survivingURL[k] = f.URL
					}
					// Invariant: a generic-credential-family value that the guard
					// classifies as noise must never survive into a finding. (Scoped
					// to that family so real JWTs / provider secrets — which skip the
					// value-shape guard — don't trip this.)
					if isGenericCredentialRule(ruleID, rule) && IsValueShapeNoise(ruleID, rule, v) {
						leakedShapes = append(leakedShapes, fmt.Sprintf("%s :: %q @ %s", rule, v, f.URL))
					}
				}
			}

			// 2) Impact: raw detector matches my new predicates now drop.
			for _, mt := range det.Detect(resp.Body()) {
				if !isGenericCredentialRule(mt.RuleID, mt.RuleName) {
					continue
				}
				s := strings.TrimSpace(mt.Secret)
				if isIdentifierSlug(s) || hasNonCredentialChar(s) {
					continue // already dropped before my change
				}
				if isDottedIdentifierPath(s) {
					dottedDrops[s]++
				} else if isCredentialKeywordName(s) {
					keywordDrops[s]++
				}
			}
		}
		_ = rows.Close()
		_ = db.Close()
	}

	t.Logf("scanned %d DBs (%d readable), %d records", len(dbs), dbsOK, records)
	t.Logf("NEW drops — dotted-path: %d distinct / %d hits, keyword-name: %d distinct / %d hits",
		len(dottedDrops), sum(dottedDrops), len(keywordDrops), sum(keywordDrops))

	t.Logf("=== dotted-path values my fix now drops (top 60) ===")
	for _, line := range topN(dottedDrops, 60) {
		t.Log("  " + line)
	}
	t.Logf("=== field-name keyword values my fix now drops (top 60) ===")
	for _, line := range topN(keywordDrops, 60) {
		t.Log("  " + line)
	}

	// The whole point: nothing with the FP shape may survive into a finding.
	if len(leakedShapes) > 0 {
		for _, l := range leakedShapes {
			t.Errorf("FP-shaped value still surfaced: %s", l)
		}
	}

	// Review surface: every surviving secret value, grouped by rule, most frequent
	// first, so residual FP classes are easy to spot by eye.
	t.Logf("=== SURVIVING secret findings across the corpus (%d distinct rule+value) ===", len(surviving))
	byRule := map[string][]kv{}
	for k := range surviving {
		byRule[k.rule] = append(byRule[k.rule], k)
	}
	var rules []string
	for r := range byRule {
		rules = append(rules, r)
	}
	sort.Strings(rules)
	for _, r := range rules {
		ks := byRule[r]
		sort.Slice(ks, func(i, j int) bool { return surviving[ks[i]] > surviving[ks[j]] })
		t.Logf("--- %s (%d distinct values) ---", r, len(ks))
		for i, k := range ks {
			if i >= 300 {
				t.Logf("    … +%d more", len(ks)-300)
				break
			}
			t.Logf("    [%3d] %q  (%s)", surviving[k], modkit.TruncateWith(k.val, 90, "…"), survivingURL[k])
		}
	}
}

func sum(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func topN(m map[string]int, n int) []string {
	type e struct {
		s string
		c int
	}
	var es []e
	for s, c := range m {
		es = append(es, e{s, c})
	}
	sort.Slice(es, func(i, j int) bool {
		if es[i].c != es[j].c {
			return es[i].c > es[j].c
		}
		return es[i].s < es[j].s
	})
	var out []string
	for i, x := range es {
		if i >= n {
			break
		}
		out = append(out, fmt.Sprintf("[%3d] %q", x.c, x.s))
	}
	return out
}
