// Package sourcemap parses JavaScript/CSS source maps and the references that
// point at them.
//
// It is deliberately a leaf: discovery reaches source maps through the crawl's
// asset graph, while the scanning phase reaches them through a module that only
// ever sees one stored response. Both need identical answers about what a
// reference looks like, what a map contains, and where an unreferenced map would
// live, so the logic lives here rather than in either caller. Nothing in this
// package performs I/O — callers fetch, this package decides.
package sourcemap

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

const (
	// MaxMapBytes caps a single source-map document. Above it the map is almost
	// certainly a build artifact dump rather than a page's own map, and parsing
	// dominates cost.
	MaxMapBytes = 8 * 1024 * 1024
	// MaxSources caps how many entries of one map are turned into originals.
	MaxSources = 512
	// MaxSourceContentBytes caps a single recovered original source.
	MaxSourceContentBytes = 2 * 1024 * 1024
	// MaxAggregateSourceBytes caps the total recovered content of one map.
	MaxAggregateSourceBytes = 8 * 1024 * 1024
	// MaxIndexedDepth bounds nesting of indexed ("sections") source maps.
	MaxIndexedDepth = 4
	// MaxExternalSections caps how many external section maps one document may
	// point at, so a hostile index cannot fan out into unbounded fetches.
	MaxExternalSections = 16
	// MaxFetchableSources caps how many original sources are followed by URL when
	// a map ships `sources` without `sourcesContent`.
	MaxFetchableSources = 64
)

// sourceMappingLiteral is the substring every reference form contains, used to
// short-circuit extraction before any regex runs.
var sourceMappingLiteral = []byte("sourceMappingURL")

// commentPattern matches the standard line-comment reference in JavaScript.
//
// The character class excludes `*` so the CSS/block-comment form does not
// swallow its closing delimiter, and excludes quotes and backslashes so a
// reference embedded in a JS string literal stops at the literal's escape rather
// than capturing `app.js.map\n");` as the filename. `;` stays allowed: a data:
// URL's own metadata contains one.
var commentPattern = regexp.MustCompile(`//[#@]\s*sourceMappingURL\s*=\s*([^\s*'"\\]+)`)

// blockCommentPattern matches the block-comment form bundlers emit for CSS, and
// occasionally for JS. Handled separately because the closing `*/` must be
// stripped rather than treated as part of the URL.
var blockCommentPattern = regexp.MustCompile(`/\*[#@]\s*sourceMappingURL\s*=\s*([^\s*'"\\]+)\s*\*/`)

// evalPattern matches a reference inside an escaped string literal, which is how
// webpack's `eval` and `eval-source-map` devtools ship per-module maps: the whole
// module is a JS string, so its newlines are the two characters \ and n and the
// multiline commentPattern never sees a line to anchor to. These builds inline a
// full base64 map per module, making them the richest accidental disclosure of
// all — and the one every `(?m)`-anchored scanner misses.
var evalPattern = regexp.MustCompile(`\\n//[#@]\s*sourceMappingURL\s*=\s*([^\\"'\s]+)`)

// ArtifactKindOriginal labels a stored original source file recovered from a
// map's sourcesContent.
//
// It lives here because three unrelated layers must agree on it — the crawl and
// the scanning-phase module write it, the secret-scan batch reads it — and a
// silent mismatch would strand every recovered source where no reader looks.
// This package is stdlib-only, so all three can import it without inverting a
// dependency.
const ArtifactKindOriginal = "source-map-original"

// Reference is one source-map pointer found in (or alongside) a bundle.
type Reference struct {
	// URL is the raw reference exactly as written: relative, absolute, or empty
	// for an inline map. Resolve it against the bundle URL before fetching.
	URL string
	// Inline carries the decoded map when the reference was a data: URL.
	Inline []byte
	// Origin records where the reference came from, for evidence and triage.
	Origin ReferenceOrigin
}

// ReferenceOrigin identifies how a source map was pointed at.
type ReferenceOrigin string

const (
	OriginComment      ReferenceOrigin = "comment"
	OriginBlockComment ReferenceOrigin = "block-comment"
	OriginEvalString   ReferenceOrigin = "eval-string"
	OriginHeader       ReferenceOrigin = "header"
	OriginInline       ReferenceOrigin = "inline-data-url"
	OriginGuessed      ReferenceOrigin = "sibling-guess"
)

// OriginalSource is one file recovered from a map's sourcesContent.
type OriginalSource struct {
	Path               string
	Content            []byte
	ContentSHA256      string
	Language           string
	GeneratedSourceURL string
}

// Document is the parse result for one map: the sources whose content the map
// carried, plus the references it points at that a caller may choose to follow.
type Document struct {
	// Sources are the originals recovered from sourcesContent.
	Sources []OriginalSource
	// SourcePaths are every path the map named, including those whose content was
	// absent. Even without content these disclose internal project layout.
	SourcePaths []string
	// FetchableSources are sources with no embedded content whose path resolved to
	// an http(s) URL — deployments that strip sourcesContent very often still
	// serve the files themselves.
	FetchableSources []string
	// ExternalSections are `sections[].url` targets of an indexed map.
	ExternalSections []string
	// HasMappings reports whether the document carried a non-empty `mappings`
	// string. A well-formed map always does; its absence, together with no named
	// sources, is how a passing-resemblance JSON blob is told from a real map.
	HasMappings bool
}

// HasEmbeddedContent reports whether the map carried any original source text,
// the difference between full source disclosure and mere path disclosure.
func (d *Document) HasEmbeddedContent() bool {
	return len(d.Sources) > 0
}

type mapDocument struct {
	Version        int       `json:"version"`
	SourceRoot     string    `json:"sourceRoot"`
	Sources        []string  `json:"sources"`
	SourcesContent []*string `json:"sourcesContent"`
	Mappings       string    `json:"mappings"`
	Sections       []section `json:"sections"`
}

type section struct {
	Map json.RawMessage `json:"map"`
	URL string          `json:"url"`
}

type budget struct {
	sources  int
	bytes    int
	sections int
}

// ExtractReferences returns every source-map pointer in a bundle body.
// Duplicates are collapsed on the raw reference.
//
// The escaped (eval) form is matched first only so a reference that both
// patterns can see is attributed to the more specific one; the resulting set is
// the same either way.
//
// A data: reference is decoded in place and returned with Inline set; a decode
// failure drops that reference rather than failing the whole extraction, so one
// truncated inline map cannot hide a second valid reference.
func ExtractReferences(body []byte) []Reference {
	// Every pattern below requires this literal, and most bodies do not contain
	// it. A single substring scan is ~3.5x cheaper than the three regex passes it
	// short-circuits, and this runs over every JS, CSS and JSON body the crawl
	// fetches — bundles routinely in the megabytes.
	if !bytes.Contains(body, sourceMappingLiteral) {
		return nil
	}

	var references []Reference
	seen := make(map[string]struct{})

	add := func(raw string, origin ReferenceOrigin) {
		raw = strings.Trim(strings.TrimSpace(raw), `"'`)
		if raw == "" {
			return
		}
		if _, dup := seen[raw]; dup {
			return
		}
		seen[raw] = struct{}{}
		if !strings.HasPrefix(raw, "data:") {
			references = append(references, Reference{URL: raw, Origin: origin})
			return
		}
		decoded, err := DecodeDataURL(raw)
		if err != nil || len(decoded) == 0 {
			return
		}
		references = append(references, Reference{Inline: decoded, Origin: OriginInline})
	}

	for _, match := range evalPattern.FindAllSubmatch(body, -1) {
		add(string(match[1]), OriginEvalString)
	}
	for _, match := range commentPattern.FindAllSubmatch(body, -1) {
		add(string(match[1]), OriginComment)
	}
	for _, match := range blockCommentPattern.FindAllSubmatch(body, -1) {
		add(string(match[1]), OriginBlockComment)
	}
	return references
}

// Candidate is one source map worth fetching for an asset, with the evidence for
// why. An Inline candidate needs no fetch: its content is already decoded.
type Candidate struct {
	// URL is the absolute map URL, resolved against the asset. Empty for Inline.
	URL string
	// Inline carries a decoded data: map.
	Inline []byte
	// Origin records how the map was pointed at, including OriginGuessed when
	// nothing referenced one.
	Origin ReferenceOrigin
}

// CandidatesFor returns the source maps to try for one fetched asset, in
// precedence order: SourceMap/X-SourceMap response headers, then references in
// the body, then — only when nothing referenced a map — the conventional
// <asset>.map sibling.
//
// The guess is last and conditional on purpose. On a build that ships the
// comment the sibling is the same URL a reference already named, so probing it
// spends a request to learn nothing; on a build that stripped the comment it is
// the only way to find a map that is still deployed.
//
// header may be nil. Both the crawl and the scanning-phase module call this so
// they cannot disagree about which maps an asset is worth asking for.
func CandidatesFor(assetURL string, header func(name string) string, body []byte) []Candidate {
	var candidates []Candidate
	seen := make(map[string]struct{})

	addURL := func(reference string, origin ReferenceOrigin) {
		resolved, ok := ResolveReference(assetURL, reference)
		if !ok {
			return
		}
		if _, dup := seen[resolved]; dup {
			return
		}
		seen[resolved] = struct{}{}
		candidates = append(candidates, Candidate{URL: resolved, Origin: origin})
	}

	if header != nil {
		for _, name := range []string{"SourceMap", "X-SourceMap"} {
			if reference := strings.TrimSpace(header(name)); reference != "" {
				addURL(reference, OriginHeader)
			}
		}
	}
	for _, reference := range ExtractReferences(body) {
		if len(reference.Inline) > 0 {
			candidates = append(candidates, Candidate{Inline: reference.Inline, Origin: reference.Origin})
			continue
		}
		addURL(reference.URL, reference.Origin)
	}
	if len(candidates) == 0 {
		if sibling, ok := SiblingCandidate(assetURL); ok {
			candidates = append(candidates, Candidate{URL: sibling, Origin: OriginGuessed})
		}
	}
	return candidates
}

// ResolveReference resolves a source-map reference against the asset that named
// it, accepting only http(s) results. A data: reference resolves to nothing —
// callers handle those as inline content, not as a URL to fetch.
func ResolveReference(assetURL, reference string) (string, bool) {
	reference = strings.TrimSpace(reference)
	if reference == "" || strings.HasPrefix(reference, "data:") {
		return "", false
	}
	base, err := url.Parse(assetURL)
	if err != nil {
		return "", false
	}
	parsed, err := url.Parse(reference)
	if err != nil {
		return "", false
	}
	resolved := base.ResolveReference(parsed)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return "", false
	}
	resolved.Fragment = ""
	return resolved.String(), true
}

// DecodeDataURL decodes an inline `data:` source map, base64 or percent-encoded.
func DecodeDataURL(value string) ([]byte, error) {
	comma := strings.IndexByte(value, ',')
	if comma < 0 {
		return nil, fmt.Errorf("malformed source-map data URL")
	}
	metadata, payload := value[:comma], value[comma+1:]
	var decoded []byte
	var err error
	if strings.Contains(strings.ToLower(metadata), ";base64") {
		decoded, err = base64.StdEncoding.DecodeString(payload)
	} else {
		var unescaped string
		unescaped, err = url.PathUnescape(payload)
		decoded = []byte(unescaped)
	}
	if err != nil {
		return nil, err
	}
	if len(decoded) > MaxMapBytes {
		return nil, fmt.Errorf("inline source map exceeds %d bytes", MaxMapBytes)
	}
	return decoded, nil
}

// Parse decodes a source-map document and recovers everything it discloses.
func Parse(content []byte, generatedSourceURL string) (*Document, error) {
	if len(content) == 0 || len(content) > MaxMapBytes {
		return nil, fmt.Errorf("source map size %d outside allowed range", len(content))
	}
	document := &Document{}
	b := &budget{}
	seen := make(map[string]struct{})
	if err := parseDocument(content, generatedSourceURL, 0, b, seen, document); err != nil {
		return nil, err
	}
	sort.Slice(document.Sources, func(i, j int) bool { return document.Sources[i].Path < document.Sources[j].Path })
	sort.Strings(document.SourcePaths)
	return document, nil
}

func parseDocument(
	content []byte,
	generatedURL string,
	depth int,
	b *budget,
	seen map[string]struct{},
	out *Document,
) error {
	if depth > MaxIndexedDepth {
		return fmt.Errorf("indexed source map nesting exceeds %d", MaxIndexedDepth)
	}
	var document mapDocument
	if err := json.Unmarshal(content, &document); err != nil {
		return fmt.Errorf("decode source map: %w", err)
	}
	if document.Version != 3 {
		return fmt.Errorf("unsupported source map version %d", document.Version)
	}
	if len(document.Mappings) > MaxMapBytes {
		return fmt.Errorf("source map mappings exceed limit")
	}
	if document.Mappings != "" {
		out.HasMappings = true
	}
	for _, sec := range document.Sections {
		if len(sec.Map) > 0 {
			if err := parseDocument(sec.Map, generatedURL, depth+1, b, seen, out); err != nil {
				return err
			}
			continue
		}
		// The spec's other section form points at a map hosted elsewhere. Callers
		// fetch these; recording them here is what makes a split-chunk build's
		// per-section maps reachable at all.
		if sec.URL == "" || b.sections >= MaxExternalSections {
			continue
		}
		b.sections++
		out.ExternalSections = append(out.ExternalSections, sec.URL)
	}

	for index, rawPath := range document.Sources {
		b.sources++
		if b.sources > MaxSources {
			return fmt.Errorf("source map source count exceeds %d", MaxSources)
		}
		safePath := NormalizePath(document.SourceRoot, rawPath)
		out.SourcePaths = append(out.SourcePaths, safePath)

		if index >= len(document.SourcesContent) || document.SourcesContent[index] == nil {
			// No embedded content. If the path still resolves to a real URL the file
			// itself is often deployed, so hand the caller something to fetch.
			if resolved, ok := resolveSourceURL(generatedURL, document.SourceRoot, rawPath); ok &&
				len(out.FetchableSources) < MaxFetchableSources {
				out.FetchableSources = append(out.FetchableSources, resolved)
			}
			continue
		}
		sourceContent := []byte(*document.SourcesContent[index])
		if len(sourceContent) == 0 || len(sourceContent) > MaxSourceContentBytes {
			continue
		}
		b.bytes += len(sourceContent)
		if b.bytes > MaxAggregateSourceBytes {
			return fmt.Errorf("source map aggregate sourcesContent exceeds %d", MaxAggregateSourceBytes)
		}
		digest := fmt.Sprintf("%x", sha256.Sum256(sourceContent))
		key := safePath + "\x00" + digest
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out.Sources = append(out.Sources, OriginalSource{
			Path: safePath, Content: sourceContent, ContentSHA256: digest,
			Language: Language(safePath), GeneratedSourceURL: generatedURL,
		})
	}
	return nil
}

// bundlerSchemes are the virtual URL schemes bundlers stamp on source paths.
// They name a module inside the build graph, not a location on the server, so a
// path carrying one is never fetchable.
var bundlerSchemes = []string{"webpack://", "webpack-internal://", "vite://", "rollup://", "file://", "ng://"}

// resolveSourceURL turns a contentless `sources` entry into an absolute http(s)
// URL when — and only when — the entry is a real relative path. Virtual bundler
// paths and absolute filesystem paths resolve to nothing fetchable.
func resolveSourceURL(generatedURL, sourceRoot, rawPath string) (string, bool) {
	candidate := strings.TrimSpace(rawPath)
	if candidate == "" {
		return "", false
	}
	for _, scheme := range bundlerSchemes {
		if strings.HasPrefix(candidate, scheme) {
			return "", false
		}
	}
	if root := strings.TrimSpace(sourceRoot); root != "" && !strings.HasPrefix(candidate, "/") &&
		!strings.Contains(candidate, "://") {
		candidate = strings.TrimSuffix(root, "/") + "/" + candidate
	}
	return ResolveReference(generatedURL, candidate)
}

// NormalizePath renders a map's source entry as a safe relative path: bundler
// schemes stripped, separators normalized, traversal resolved, length bounded.
// The result is used as a filename, so it must never escape a directory.
func NormalizePath(sourceRoot, source string) string {
	value := strings.ReplaceAll(strings.TrimSpace(source), "\\", "/")
	for _, scheme := range bundlerSchemes {
		value = strings.TrimPrefix(value, scheme)
	}
	if decoded, err := url.PathUnescape(value); err == nil {
		value = decoded
	}
	root := strings.ReplaceAll(strings.TrimSpace(sourceRoot), "\\", "/")
	value = path.Clean("/" + path.Join(root, value))
	value = strings.TrimLeft(value, "/")
	if value == "" || value == "." {
		value = "source.js"
	}
	if len(value) > 512 {
		value = value[len(value)-512:]
	}
	return value
}

// Language classifies a recovered source by extension.
func Language(name string) string {
	switch strings.ToLower(path.Ext(name)) {
	case ".ts":
		return "ts"
	case ".tsx":
		return "tsx"
	case ".jsx":
		return "jsx"
	case ".vue":
		return "vue"
	case ".svelte":
		return "svelte"
	case ".css", ".scss", ".sass", ".less":
		return "css"
	default:
		return "js"
	}
}

// IsMapPath reports whether a URL path names a source map. Servers label .map
// files inconsistently (application/json, application/octet-stream, text/plain),
// so the extension is the only dependable signal.
func IsMapPath(urlPath string) bool {
	const ext = ".map"
	return len(urlPath) >= len(ext) && strings.EqualFold(urlPath[len(urlPath)-len(ext):], ext)
}

// mappableExtensions are the asset types a bundler emits a sibling map for.
var mappableExtensions = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".css": true,
}

// IsMappableAssetPath reports whether a URL path names an asset a bundler emits a
// sibling map for. Path-only, so it answers for a raw request whose scheme is not
// yet known — which is how modules gate on an asset before resolving it.
func IsMappableAssetPath(urlPath string) bool {
	if IsMapPath(urlPath) {
		return false
	}
	return mappableExtensions[strings.ToLower(path.Ext(urlPath))]
}

// SiblingCandidate returns the conventional map URL for an asset, and whether the
// asset is the kind that has one.
//
// This is what covers the most common real-world exposure: a build configured
// with `hidden-source-map` (or an uploader that strips the comment after shipping
// the map to an error tracker) deploys the .map next to the bundle with nothing
// pointing at it. No amount of reference extraction finds those — only asking for
// the conventional name does.
func SiblingCandidate(assetURL string) (string, bool) {
	parsed, err := url.Parse(assetURL)
	if err != nil {
		return "", false
	}
	return SiblingCandidateURL(parsed)
}

// SiblingCandidateURL is SiblingCandidate for a URL the caller already parsed.
func SiblingCandidateURL(assetURL *url.URL) (string, bool) {
	if assetURL == nil || assetURL.Scheme == "" || assetURL.Host == "" {
		return "", false
	}
	if !IsMappableAssetPath(assetURL.Path) {
		return "", false
	}
	sibling := *assetURL
	sibling.Path += ".map"
	sibling.RawQuery = ""
	sibling.Fragment = ""
	return sibling.String(), true
}

// LooksLikeMap reports whether a body is plausibly a source-map document, without
// fully parsing it. Used to reject a catch-all HTML shell answering 200 for a
// guessed .map path before spending a parse on it.
func LooksLikeMap(body []byte) bool {
	const probeWindow = 512
	head := body
	if len(head) > probeWindow {
		head = head[:probeWindow]
	}
	// Leading BOM included: static hosts serve UTF-8 maps with one often enough
	// that a byte-for-byte "{" check would reject real maps.
	trimmed := strings.TrimLeft(string(head), " \t\r\n\ufeff")
	if !strings.HasPrefix(trimmed, "{") {
		return false
	}
	return strings.Contains(trimmed, `"version"`) ||
		strings.Contains(trimmed, `"sources"`) ||
		strings.Contains(trimmed, `"mappings"`)
}
