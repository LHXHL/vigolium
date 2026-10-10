package wordlists

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// gzSuffix marks an embedded list stored gzip-compressed. Its logical name is
// the name without the suffix (dir-large.txt.gz is served as dir-large.txt).
const gzSuffix = ".gz"

// DefaultPaths holds on-disk paths to the materialized embedded default wordlists.
// A field is empty only if that list could not be written.
//
// The dir/file lists come in three tiers (discovery.wordlists.tier):
//   - short: dir-short.txt / file-short.txt (a few hundred entries)
//   - long:  dir-long.txt / file-long.txt (~5k entries)
//   - large: dir-large.txt / file-large.txt, embedded gzip-compressed. The
//     bundled large lists are the deduplicated union of both long lists plus
//     the bare single-segment words of fuzz.txt (~9.3k entries), so the tier
//     carries no third-party content beyond what the long tier already ships.
//     A curated larger list can replace them by dropping dir-large.txt.gz /
//     file-large.txt.gz into this directory; keep each a superset of its long
//     counterpart (TestLargeTierIsSupersetOfLong enforces it).
type DefaultPaths struct {
	ShortFile string
	LongFile  string
	LargeFile string
	ShortDir  string
	LongDir   string
	LargeDir  string
	Fuzz      string
}

// EnsureOnDisk materializes the embedded default wordlists into dir (created if
// absent) and returns their on-disk paths. deparos loads wordlists from file
// paths only — it has no in-memory provider for the built-in list types (see
// pkg/deparos/discovery/payload/wordlist_cache.go, which os.Open's the path) —
// so the embedded lists must be written out before they can serve as defaults.
// Gzip-embedded lists are written decompressed. Each file is (re)written only
// when missing or size-mismatched, and writes are atomic (temp + rename) so a
// concurrent scan never observes a partial file.
func EnsureOnDisk(dir string) (DefaultPaths, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return DefaultPaths{}, fmt.Errorf("create wordlist dir %s: %w", dir, err)
	}

	var paths DefaultPaths
	targets := []struct {
		name string
		dst  *string
	}{
		{"file-short.txt", &paths.ShortFile},
		{"file-long.txt", &paths.LongFile},
		{"file-large.txt", &paths.LargeFile},
		{"dir-short.txt", &paths.ShortDir},
		{"dir-long.txt", &paths.LongDir},
		{"dir-large.txt", &paths.LargeDir},
		{"fuzz.txt", &paths.Fuzz},
	}
	for _, t := range targets {
		p, err := materialize(dir, t.name)
		if err != nil {
			return paths, err
		}
		*t.dst = p
	}
	return paths, nil
}

// ReadList returns the contents of the embedded wordlist with logical name
// name, gunzipping it when it is stored as name+".gz" (or when name itself
// ends in ".gz"). A plain name.txt wins over name.txt.gz when both exist.
func ReadList(name string) ([]byte, error) {
	if strings.HasSuffix(name, gzSuffix) {
		return readGzip(name)
	}
	data, err := WordlistsFS.ReadFile(name)
	if err == nil {
		return data, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if gz, gzErr := readGzip(name + gzSuffix); gzErr == nil {
		return gz, nil
	} else if !errors.Is(gzErr, fs.ErrNotExist) {
		return nil, gzErr
	}
	return nil, err
}

// ListNames returns the sorted logical names of every embedded wordlist, with
// the ".gz" suffix of compressed lists stripped (so they read through ReadList).
func ListNames() ([]string, error) {
	entries, err := fs.ReadDir(WordlistsFS, ".")
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(entries))
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := strings.TrimSuffix(e.Name(), gzSuffix)
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names, nil
}

func readGzip(name string) ([]byte, error) {
	raw, err := WordlistsFS.ReadFile(name)
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("gunzip embedded wordlist %s: %w", name, err)
	}
	defer func() { _ = zr.Close() }()
	data, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("gunzip embedded wordlist %s: %w", name, err)
	}
	return data, nil
}

// decodedSizes caches each embedded list's decompressed length by logical
// name, so a repeat EnsureOnDisk can confirm an on-disk copy is current from a
// stat alone instead of gunzipping the large lists again.
var decodedSizes sync.Map // name -> int64

// materialize writes a single embedded wordlist into dir under its logical
// name, returning its path. It skips the write when an up-to-date copy (same
// size as the decompressed content) is already present.
func materialize(dir, name string) (string, error) {
	dst := filepath.Join(dir, name)
	current := func(size int64) bool {
		info, statErr := os.Stat(dst)
		return statErr == nil && info.Mode().IsRegular() && info.Size() == size
	}
	if size, ok := decodedSizes.Load(name); ok && current(size.(int64)) {
		return dst, nil // already current
	}

	data, err := ReadList(name)
	if err != nil {
		return "", fmt.Errorf("read embedded wordlist %s: %w", name, err)
	}
	decodedSizes.Store(name, int64(len(data)))
	if current(int64(len(data))) {
		return dst, nil // already current
	}

	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return "", fmt.Errorf("write wordlist %s: %w", name, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("install wordlist %s: %w", name, err)
	}
	return dst, nil
}
