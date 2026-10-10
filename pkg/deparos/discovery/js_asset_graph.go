package discovery

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
)

type AssetKind string

const (
	AssetScript        AssetKind = "script"
	AssetDynamicImport AssetKind = "dynamic-import"
	AssetWorker        AssetKind = "worker"
	AssetSharedWorker  AssetKind = "shared-worker"
	AssetServiceWorker AssetKind = "service-worker"
	AssetSourceMap     AssetKind = "source-map"
	AssetWASM          AssetKind = "wasm"
	AssetManifest      AssetKind = "manifest"
	AssetConfig        AssetKind = "config"
	// AssetChunk is a lazy chunk a loader runtime renders from an id (webpack
	// chunk-filename maps, Vite preload dependencies); see AssetReferenceFact.Loader.
	AssetChunk AssetKind = "chunk"
)

type JSAssetNode struct {
	URL         string
	ContentHash string
	Depth       int
	Parents     []string
	Kind        AssetKind
}

type JSAssetGraphConfig struct {
	MaxDepth           int
	MaxAssetsPerParent int
	// MaxChunksPerRuntime bounds the loader-rendered children (webpack/Vite
	// chunks, enumerated template imports) one parent bundle may add. It
	// replaces MaxAssetsPerParent for those children, because a chunk runtime
	// routinely names hundreds of chunks; MaxAssetsPerHost/Total still apply.
	MaxChunksPerRuntime int
	MaxAssetsPerHost    int
	MaxAssetsTotal      int
}

// DefaultMaxChunksPerRuntime is the per-parent budget for loader-rendered chunks.
const DefaultMaxChunksPerRuntime = 512

func DefaultJSAssetGraphConfig() JSAssetGraphConfig {
	return JSAssetGraphConfig{
		MaxDepth: 4, MaxAssetsPerParent: 64, MaxChunksPerRuntime: DefaultMaxChunksPerRuntime,
		MaxAssetsPerHost: 512, MaxAssetsTotal: 2048,
	}
}

type JSAssetGraph struct {
	mu     sync.Mutex
	config JSAssetGraphConfig
	nodes  map[string]*JSAssetNode
	edges  map[string]map[string]struct{}
	// loaded counts, per parent, the children admitted under the loader
	// budget so they are not charged to MaxAssetsPerParent as well.
	loaded     map[string]int
	hostCounts map[string]int
	content    map[string]string
}

func NewJSAssetGraph(config JSAssetGraphConfig) *JSAssetGraph {
	defaults := DefaultJSAssetGraphConfig()
	if config.MaxDepth <= 0 {
		config.MaxDepth = defaults.MaxDepth
	}
	if config.MaxAssetsPerParent <= 0 {
		config.MaxAssetsPerParent = defaults.MaxAssetsPerParent
	}
	if config.MaxChunksPerRuntime <= 0 {
		config.MaxChunksPerRuntime = defaults.MaxChunksPerRuntime
	}
	if config.MaxAssetsPerHost <= 0 {
		config.MaxAssetsPerHost = defaults.MaxAssetsPerHost
	}
	if config.MaxAssetsTotal <= 0 {
		config.MaxAssetsTotal = defaults.MaxAssetsTotal
	}
	return &JSAssetGraph{
		config: config, nodes: make(map[string]*JSAssetNode), edges: make(map[string]map[string]struct{}),
		loaded: make(map[string]int), hostCounts: make(map[string]int), content: make(map[string]string),
	}
}

// Add resolves child with browser URL semantics and returns true only when the
// normalized URL is a newly admitted graph node that should be fetched.
func (g *JSAssetGraph) Add(parentURL, childURL string, kind AssetKind) (*url.URL, bool, string) {
	return g.AddLoaded(parentURL, childURL, kind, "")
}

// AddLoaded is Add for a child named by a loader runtime (loader non-empty, for
// example "webpack-chunk"). Such children are bounded per parent by
// MaxChunksPerRuntime ("chunk-limit") instead of MaxAssetsPerParent, and still
// count against the per-host and total budgets.
func (g *JSAssetGraph) AddLoaded(parentURL, childURL string, kind AssetKind, loader string) (*url.URL, bool, string) {
	resolved, err := resolveAssetURL(parentURL, childURL)
	if err != nil {
		return nil, false, "invalid-url"
	}
	key := normalizeAssetURL(resolved)
	parentKey := ""
	if parent, parentErr := url.Parse(parentURL); parentErr == nil && parent.Scheme != "" && parent.Host != "" {
		parentKey = normalizeAssetURL(parent)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if existing := g.nodes[key]; existing != nil {
		if g.addParentLocked(existing, parentKey) && loader != "" {
			g.loaded[parentKey]++
		}
		return resolved, false, "duplicate-url"
	}
	depth := 1
	if parent := g.nodes[parentKey]; parent != nil {
		depth = parent.Depth + 1
	}
	if depth > g.config.MaxDepth {
		return nil, false, "depth-limit"
	}
	if len(g.nodes) >= g.config.MaxAssetsTotal {
		return nil, false, "total-limit"
	}
	if parentKey != "" {
		if loader != "" {
			if g.loaded[parentKey] >= g.config.MaxChunksPerRuntime {
				return nil, false, "chunk-limit"
			}
		} else if len(g.edges[parentKey])-g.loaded[parentKey] >= g.config.MaxAssetsPerParent {
			return nil, false, "parent-limit"
		}
	}
	host := strings.ToLower(resolved.Hostname())
	if g.hostCounts[host] >= g.config.MaxAssetsPerHost {
		return nil, false, "host-limit"
	}
	node := &JSAssetNode{URL: key, Depth: depth, Kind: kind}
	g.nodes[key] = node
	g.hostCounts[host]++
	if g.addParentLocked(node, parentKey) && loader != "" {
		g.loaded[parentKey]++
	}
	return resolved, true, ""
}

func (g *JSAssetGraph) AddRoot(rawURL string, kind AssetKind) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return
	}
	key := normalizeAssetURL(u)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.nodes[key] == nil {
		g.nodes[key] = &JSAssetNode{URL: key, Depth: 0, Kind: kind}
		g.hostCounts[strings.ToLower(u.Hostname())]++
	}
}

// addParentLocked records the parent edge and reports whether it was new.
func (g *JSAssetGraph) addParentLocked(node *JSAssetNode, parent string) bool {
	if parent == "" {
		return false
	}
	if g.edges[parent] == nil {
		g.edges[parent] = make(map[string]struct{})
	}
	if _, exists := g.edges[parent][node.URL]; exists {
		return false
	}
	g.edges[parent][node.URL] = struct{}{}
	node.Parents = append(node.Parents, parent)
	sort.Strings(node.Parents)
	return true
}

// MarkContent returns false when another URL already supplied identical bytes.
func (g *JSAssetGraph) MarkContent(rawURL string, content []byte) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	key := normalizeAssetURL(u)
	digest := fmt.Sprintf("%x", sha256.Sum256(content))
	g.mu.Lock()
	defer g.mu.Unlock()
	if firstURL, exists := g.content[digest]; exists && firstURL != key {
		if node := g.nodes[key]; node != nil {
			node.ContentHash = digest
		}
		return false
	}
	g.content[digest] = key
	if node := g.nodes[key]; node != nil {
		node.ContentHash = digest
	}
	return true
}

func (g *JSAssetGraph) Parents(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if node := g.nodes[normalizeAssetURL(u)]; node != nil {
		return append([]string(nil), node.Parents...)
	}
	return nil
}

func (g *JSAssetGraph) Nodes() []JSAssetNode {
	g.mu.Lock()
	defer g.mu.Unlock()
	result := make([]JSAssetNode, 0, len(g.nodes))
	for _, node := range g.nodes {
		clone := *node
		clone.Parents = append([]string(nil), node.Parents...)
		result = append(result, clone)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].URL < result[j].URL })
	return result
}

func resolveAssetURL(parentURL, childURL string) (*url.URL, error) {
	if strings.Contains(childURL, "${") || strings.HasPrefix(childURL, "inline:") || strings.HasPrefix(childURL, "data:") {
		return nil, fmt.Errorf("unresolved or inline asset")
	}
	child, err := url.Parse(strings.TrimSpace(childURL))
	if err != nil {
		return nil, err
	}
	if child.IsAbs() {
		if child.Scheme != "http" && child.Scheme != "https" {
			return nil, fmt.Errorf("unsupported scheme")
		}
		child.Fragment = ""
		return child, nil
	}
	parent, err := url.Parse(parentURL)
	if err != nil || parent.Scheme == "" || parent.Host == "" {
		return nil, fmt.Errorf("invalid parent")
	}
	resolved := parent.ResolveReference(child)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme")
	}
	resolved.Fragment = ""
	return resolved, nil
}

func normalizeAssetURL(u *url.URL) string {
	clone := *u
	clone.Scheme = strings.ToLower(clone.Scheme)
	clone.Host = strings.ToLower(clone.Host)
	clone.Fragment = ""
	return clone.String()
}
