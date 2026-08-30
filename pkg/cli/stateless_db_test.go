package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

// writeGlobFixture writes a minimal {type,data} JSONL export with one HTTP
// record and one finding (distinct finding_hash so merges don't dedup).
func writeGlobFixture(t *testing.T, path, host, hash, module string) {
	t.Helper()
	body := `{"type":"http_record","data":{"url":"http://` + host + `/x","method":"GET","status_code":200,"host":"` + host + `"}}
{"type":"finding","data":{"finding_hash":"` + hash + `","module_id":"` + module + `","module_name":"` + module + `","severity":"high","confidence":"firm","url":"http://` + host + `/x","hostname":"` + host + `","description":"d"}}
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestOpenGlobDBMergesMatches(t *testing.T) {
	dir := t.TempDir()
	writeGlobFixture(t, filepath.Join(dir, "scan-a.jsonl"), "a.example", "hash-a", "xss-reflected")
	writeGlobFixture(t, filepath.Join(dir, "scan-b.jsonl"), "b.example", "hash-b", "sqli-error")

	// openGlobDB caches its connection process-wide; reset so it doesn't leak
	// into other tests in this package.
	defer resetDBCacheForTest()

	db, err := openGlobDB(filepath.Join(dir, "scan-*.jsonl"), globDBSkipSet{})
	if err != nil {
		t.Fatalf("openGlobDB: %v", err)
	}

	ctx := context.Background()
	var findings []*database.Finding
	if err := db.NewSelect().Model(&findings).Scan(ctx); err != nil {
		t.Fatalf("scan findings: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings merged across the glob, got %d", len(findings))
	}

	var records []*database.HTTPRecord
	if err := db.NewSelect().Model(&records).Scan(ctx); err != nil {
		t.Fatalf("scan records: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 HTTP records merged across the glob, got %d", len(records))
	}
}

// A --glob-db pattern must be quoted to survive the shell, which also suppresses
// the shell's tilde expansion — so the leading ~ reaches openGlobDB literally and
// has to be resolved here or filepath.Glob matches nothing.
func TestOpenGlobDBExpandsHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeGlobFixture(t, filepath.Join(home, "stryk-a.jsonl"), "a.example", "hash-a", "xss-reflected")
	writeGlobFixture(t, filepath.Join(home, "stryk-b.jsonl"), "b.example", "hash-b", "sqli-error")

	defer resetDBCacheForTest()

	db, err := openGlobDB("~/stryk-*.jsonl", globDBSkipSet{})
	if err != nil {
		t.Fatalf("openGlobDB with ~ pattern: %v", err)
	}
	var findings []*database.Finding
	if err := db.NewSelect().Model(&findings).Scan(context.Background()); err != nil {
		t.Fatalf("scan findings: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings merged from the ~ glob, got %d", len(findings))
	}
}

func TestExpandUserHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"bare tilde", "~", home},
		{"tilde slash pattern", "~/scans/*.sqlite", filepath.Join(home, "scans", "*.sqlite")},
		{"absolute untouched", "/tmp/scans/*.sqlite", "/tmp/scans/*.sqlite"},
		{"relative untouched", "scans/*.sqlite", "scans/*.sqlite"},
		// ~user is not resolved, and a mid-path ~ is a legitimate filename char.
		{"tilde user untouched", "~other/scans/*.sqlite", "~other/scans/*.sqlite"},
		{"embedded tilde untouched", "scans/~backup/*.sqlite", "scans/~backup/*.sqlite"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := expandUserHome(tc.in); got != tc.want {
				t.Fatalf("expandUserHome(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestOpenGlobDBErrors(t *testing.T) {
	t.Run("no match", func(t *testing.T) {
		defer resetDBCacheForTest()
		if _, err := openGlobDB(filepath.Join(t.TempDir(), "nope-*.sqlite"), globDBSkipSet{}); err == nil {
			t.Fatal("expected an error when the glob matches no files")
		}
	})

	t.Run("invalid pattern", func(t *testing.T) {
		defer resetDBCacheForTest()
		if _, err := openGlobDB("[", globDBSkipSet{}); err == nil {
			t.Fatal("expected an error for a malformed glob pattern")
		}
	})

	t.Run("all matches unimportable", func(t *testing.T) {
		defer resetDBCacheForTest()
		dir := t.TempDir()
		// A matched-but-garbage file is skipped; with none loadable, error out.
		if err := os.WriteFile(filepath.Join(dir, "junk-1.jsonl"), []byte("not json at all\n"), 0o644); err != nil {
			t.Fatalf("write junk: %v", err)
		}
		if _, err := openGlobDB(filepath.Join(dir, "junk-*.jsonl"), globDBSkipSet{}); err == nil {
			t.Fatal("expected an error when no matched file could be loaded")
		}
	})
}
