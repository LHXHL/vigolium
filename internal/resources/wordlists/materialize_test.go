package wordlists

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureOnDisk_WritesAllListsWithEmbeddedContent(t *testing.T) {
	dir := t.TempDir()

	paths, err := EnsureOnDisk(dir)
	if err != nil {
		t.Fatalf("EnsureOnDisk: %v", err)
	}

	cases := []struct {
		name string
		got  string
	}{
		{"file-short.txt", paths.ShortFile},
		{"file-long.txt", paths.LongFile},
		{"file-large.txt", paths.LargeFile},
		{"dir-short.txt", paths.ShortDir},
		{"dir-long.txt", paths.LongDir},
		{"dir-large.txt", paths.LargeDir},
		{"fuzz.txt", paths.Fuzz},
	}
	for _, c := range cases {
		if c.got != filepath.Join(dir, c.name) {
			t.Errorf("%s: path = %q, want %q", c.name, c.got, filepath.Join(dir, c.name))
		}
		onDisk, err := os.ReadFile(c.got)
		if err != nil {
			t.Fatalf("read %s: %v", c.got, err)
		}
		embedded, err := ReadList(c.name)
		if err != nil {
			t.Fatalf("read embedded %s: %v", c.name, err)
		}
		if len(onDisk) != len(embedded) {
			t.Errorf("%s: on-disk size %d != embedded size %d", c.name, len(onDisk), len(embedded))
		}
		if len(onDisk) == 0 {
			t.Errorf("%s: materialized file is empty", c.name)
		}
	}
}

func TestEnsureOnDisk_IsIdempotentAndRepairsTampering(t *testing.T) {
	dir := t.TempDir()

	first, err := EnsureOnDisk(dir)
	if err != nil {
		t.Fatalf("first EnsureOnDisk: %v", err)
	}

	// A second call must succeed and return the same paths without re-erroring.
	second, err := EnsureOnDisk(dir)
	if err != nil {
		t.Fatalf("second EnsureOnDisk: %v", err)
	}
	if first != second {
		t.Errorf("paths changed across calls: %+v vs %+v", first, second)
	}

	// Corrupt a file (size mismatch) and confirm the next call rewrites it from
	// the embedded copy.
	if err := os.WriteFile(first.ShortFile, []byte("tampered"), 0o644); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if _, err := EnsureOnDisk(dir); err != nil {
		t.Fatalf("repair EnsureOnDisk: %v", err)
	}
	repaired, err := os.ReadFile(first.ShortFile)
	if err != nil {
		t.Fatalf("read repaired: %v", err)
	}
	embedded, _ := WordlistsFS.ReadFile("file-short.txt")
	if len(repaired) != len(embedded) {
		t.Errorf("tampered file not repaired: size %d != embedded %d", len(repaired), len(embedded))
	}
}

// The large tier ships gzip-compressed; EnsureOnDisk must write the gunzipped
// text (a plain wordlist deparos can os.Open line by line), never the gzip bytes.
func TestEnsureOnDisk_GunzipsCompressedLists(t *testing.T) {
	if _, err := WordlistsFS.ReadFile("dir-large.txt.gz"); err != nil {
		t.Fatalf("dir-large.txt.gz not embedded: %v", err)
	}
	if _, err := WordlistsFS.ReadFile("dir-large.txt"); err == nil {
		t.Fatal("dir-large.txt is embedded uncompressed; this test expects only the .gz form")
	}

	dir := t.TempDir()
	paths, err := EnsureOnDisk(dir)
	if err != nil {
		t.Fatalf("EnsureOnDisk: %v", err)
	}
	for _, p := range []string{paths.LargeDir, paths.LargeFile} {
		if filepath.Ext(p) != ".txt" {
			t.Errorf("materialized name %q should drop the .gz suffix", p)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
			t.Fatalf("%s holds gzip bytes, want decompressed text", p)
		}
		if n := len(strings.Split(strings.TrimSpace(string(data)), "\n")); n < 9000 {
			t.Errorf("%s: %d lines, want the ~9.3k-entry large tier", p, n)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "dir-large.txt.gz")); err == nil {
		t.Error("the compressed form must not be written to disk")
	}

	// Idempotent: a second run sees the decompressed size and leaves it alone.
	before, _ := os.Stat(paths.LargeDir)
	if _, err := EnsureOnDisk(dir); err != nil {
		t.Fatalf("second EnsureOnDisk: %v", err)
	}
	after, _ := os.Stat(paths.LargeDir)
	if !before.ModTime().Equal(after.ModTime()) {
		t.Error("an up-to-date decompressed list was rewritten")
	}
}

func TestReadListAndListNames_HideGzipSuffix(t *testing.T) {
	plain, err := ReadList("dir-large.txt")
	if err != nil {
		t.Fatalf("ReadList(dir-large.txt): %v", err)
	}
	viaGz, err := ReadList("dir-large.txt.gz")
	if err != nil {
		t.Fatalf("ReadList(dir-large.txt.gz): %v", err)
	}
	if string(plain) != string(viaGz) {
		t.Error("ReadList returns different content for the logical and .gz names")
	}
	if _, err := ReadList("no-such-list.txt"); err == nil {
		t.Error("ReadList of a missing list should fail")
	}

	names, err := ListNames()
	if err != nil {
		t.Fatalf("ListNames: %v", err)
	}
	got := map[string]bool{}
	for _, n := range names {
		if strings.HasSuffix(n, ".gz") {
			t.Errorf("ListNames leaked a .gz name: %q", n)
		}
		got[n] = true
	}
	for _, want := range []string{"dir-large.txt", "file-large.txt", "dir-long.txt", "fuzz.txt", "jwt.secrets.list"} {
		if !got[want] {
			t.Errorf("ListNames missing %q (got %v)", want, names)
		}
	}
}

// The tiers must be monotonic: selecting "large" never drops a word "long"
// would have tried. A curated replacement list has to keep this property.
func TestLargeTierIsSupersetOfLong(t *testing.T) {
	for _, pair := range [][2]string{{"dir-long.txt", "dir-large.txt"}, {"file-long.txt", "file-large.txt"}} {
		long, err := ReadList(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		large, err := ReadList(pair[1])
		if err != nil {
			t.Fatal(err)
		}
		have := map[string]bool{}
		for _, w := range strings.Split(string(large), "\n") {
			if w = strings.TrimSpace(w); w != "" {
				if have[w] {
					t.Errorf("%s: duplicate entry %q", pair[1], w)
				}
				have[w] = true
			}
		}
		for _, w := range strings.Split(string(long), "\n") {
			if w = strings.TrimSpace(w); w != "" && !have[w] {
				t.Errorf("%s is missing %q from %s", pair[1], w, pair[0])
				break
			}
		}
	}
}
