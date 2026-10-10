package payload

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"strings"
)

// LazyCustomProvider wraps CachedWordlist with custom name for module wordlists.
// Shares underlying [][]byte data with other providers using same cache entry.
//
// NOT thread-safe. Thread-safety is provided by PayloadDispatcher which serializes
// all calls to Next(). This provider should only be accessed through a dispatcher.
type LazyCustomProvider struct {
	source *CachedWordlist
	index  int
	name   string
}

// NewLazyCustomProvider creates a provider for cached custom wordlist files.
func NewLazyCustomProvider(source *CachedWordlist, name string) *LazyCustomProvider {
	return &LazyCustomProvider{
		source: source,
		index:  0,
		name:   name,
	}
}

// NewLazyCustomProviderFromInline creates a provider from inline words.
// This doesn't use cache since inline words are typically small and unique per module.
func NewLazyCustomProviderFromInline(name string, words []string) *LazyCustomProvider {
	payloads := make([][]byte, 0, len(words))
	for _, w := range words {
		w = strings.TrimSpace(w)
		if w != "" {
			payloads = append(payloads, []byte(w))
		}
	}
	return &LazyCustomProvider{
		source: &CachedWordlist{
			Payloads: payloads,
			FilePath: "",
			ListType: CustomListType,
		},
		index: 0,
		name:  name,
	}
}

// Next returns the next payload or io.EOF when exhausted.
func (p *LazyCustomProvider) Next(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if p.index >= len(p.source.Payloads) {
		return nil, io.EOF
	}

	payload := p.source.Payloads[p.index]
	p.index++
	return payload, nil
}

// Count returns the total number of payloads.
func (p *LazyCustomProvider) Count() int {
	return len(p.source.Payloads)
}

// Name returns a descriptive name for this provider.
func (p *LazyCustomProvider) Name() string {
	return fmt.Sprintf("lazy-custom:%s", p.name)
}

// Close releases any resources held by the provider.
// Data is owned by cache (or inline), so nothing to release here.
func (p *LazyCustomProvider) Close() error {
	return nil
}

// HashContent returns a hash of the provider's configuration.
func (p *LazyCustomProvider) HashContent() uint64 {
	h := fnv.New64a()
	h.Write([]byte(p.name))

	// For file-based: hash the file path
	if p.source.FilePath != "" {
		h.Write([]byte{0})
		h.Write([]byte(p.source.FilePath))
	} else {
		// For inline: hash the content
		for _, payload := range p.source.Payloads {
			h.Write([]byte{0})
			h.Write(payload)
		}
	}
	return h.Sum64()
}

// SeenSet records words the streaming provider has already emitted. IsSeen
// reports whether key was seen before and records it when it was not (the
// dedup.DiskSet contract), so a 1M-line list dedups on disk, not in memory.
type SeenSet interface {
	IsSeen(key string) bool
}

// memorySeenSet is the fallback SeenSet when the caller supplies none.
type memorySeenSet map[string]struct{}

func (m memorySeenSet) IsSeen(key string) bool {
	if _, ok := m[key]; ok {
		return true
	}
	m[key] = struct{}{}
	return false
}

// StreamingFilesProvider streams one or more wordlist files in order, one line
// at a time, without loading them into memory. Every word is emitted at most
// once across all files: duplicates are filtered through seen (an on-disk set
// for large lists). Lines are trimmed and empty lines skipped, matching
// loadWordlist; a path ending in ".gz" is gunzipped while reading.
//
// Each file is opened only when the previous one is exhausted and closed as
// soon as it is, so a provider that is never drained to io.EOF holds at most
// one open file; Close releases it.
//
// NOT thread-safe; access it through a PayloadDispatcher like the other
// providers.
type StreamingFilesProvider struct {
	paths []string
	name  string
	seen  SeenSet

	next    int // index of the next file to open
	file    *os.File
	gz      *gzip.Reader
	scanner *bufio.Scanner
	current string
}

// NewStreamingFilesProvider validates that every path is a readable regular
// file and returns a provider that streams them in order. seen may be nil, in
// which case an in-memory set is used (fine for small lists and tests).
func NewStreamingFilesProvider(name string, paths []string, seen SeenSet) (*StreamingFilesProvider, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("custom wordlist file path required")
	}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("custom wordlist %s: %w", p, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("custom wordlist %s: not a regular file", p)
		}
	}
	if seen == nil {
		seen = memorySeenSet{}
	}
	return &StreamingFilesProvider{
		paths: append([]string(nil), paths...),
		name:  name,
		seen:  seen,
	}, nil
}

// Next returns the next not-yet-emitted word, or io.EOF after the last file.
// A file that fails to open or read is skipped (the error is returned once so
// the caller can log it) and streaming continues with the next file.
func (p *StreamingFilesProvider) Next(ctx context.Context) ([]byte, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if p.scanner == nil {
			if p.next >= len(p.paths) {
				return nil, io.EOF
			}
			path := p.paths[p.next]
			p.next++
			if err := p.open(path); err != nil {
				return nil, err
			}
		}

		if !p.scanner.Scan() {
			err := p.scanner.Err()
			path := p.current
			p.closeCurrent()
			if err != nil {
				return nil, fmt.Errorf("read custom wordlist %s: %w", path, err)
			}
			continue
		}

		line := bytes.TrimSpace(p.scanner.Bytes())
		if len(line) == 0 || p.seen.IsSeen(string(line)) {
			continue
		}
		return bytes.Clone(line), nil
	}
}

func (p *StreamingFilesProvider) open(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open custom wordlist %s: %w", path, err)
	}
	var r io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			_ = f.Close()
			return fmt.Errorf("gunzip custom wordlist %s: %w", path, err)
		}
		p.gz = zr
		r = zr
	}
	sc := bufio.NewScanner(r)
	// Same 1MB max line as loadWordlist.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	p.file = f
	p.scanner = sc
	p.current = path
	return nil
}

func (p *StreamingFilesProvider) closeCurrent() {
	if p.gz != nil {
		_ = p.gz.Close()
		p.gz = nil
	}
	if p.file != nil {
		_ = p.file.Close()
		p.file = nil
	}
	p.scanner = nil
	p.current = ""
}

// Count returns 0: the number of unique words is unknown until the files are
// streamed.
func (p *StreamingFilesProvider) Count() int { return 0 }

// Name returns a descriptive name for this provider.
func (p *StreamingFilesProvider) Name() string {
	return fmt.Sprintf("stream-custom:%s", p.name)
}

// Close releases the file currently being read, if any.
func (p *StreamingFilesProvider) Close() error {
	p.closeCurrent()
	p.next = len(p.paths)
	return nil
}

// HashContent hashes the provider name and the ordered file paths, matching
// LazyCustomProvider's file-based hashing.
func (p *StreamingFilesProvider) HashContent() uint64 {
	h := fnv.New64a()
	h.Write([]byte(p.name))
	for _, path := range p.paths {
		h.Write([]byte{0})
		h.Write([]byte(path))
	}
	return h.Sum64()
}
