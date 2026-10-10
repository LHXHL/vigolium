package source

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	deparosstorage "github.com/vigolium/vigolium/pkg/deparos/storage"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// pathSaver records every persisted record's path per source label, in save
// order.
type pathSaver struct {
	captureSaver
	pmu   sync.Mutex
	paths map[string][]string
}

func newPathSaver() *pathSaver {
	return &pathSaver{captureSaver: captureSaver{bySource: map[string]int{}}, paths: map[string][]string{}}
}

func (s *pathSaver) SaveRecordBatch(ctx context.Context, records []*httpmsg.HttpRequestResponse, source, project string) ([]string, error) {
	s.pmu.Lock()
	for _, rr := range records {
		u, err := rr.URL()
		if err == nil {
			s.paths[source] = append(s.paths[source], u.Path)
		}
	}
	s.pmu.Unlock()
	return s.captureSaver.SaveRecordBatch(ctx, records, source, project)
}

func (s *pathSaver) saved(source string) []string {
	s.pmu.Lock()
	defer s.pmu.Unlock()
	return append([]string(nil), s.paths[source]...)
}

// fuzzNode is one wordlist-class node for the streaming tests.
type fuzzNode struct {
	path   string
	status int
	body   string
}

func storeFuzzNode(t *testing.T, sm *deparosstorage.SiteMap, n fuzzNode) {
	t.Helper()
	u, err := url.Parse("https://app.example" + n.path)
	require.NoError(t, err)
	body := []byte(n.body)
	require.NoError(t, sm.Store(deparosstorage.NewResultBuilder().
		WithURL(u).
		WithRequest("GET", nil, nil).
		WithResponse(n.status, map[string]string{"Content-Type": "text/html"}, body, int64(len(body)), "text/html", "", "", 0, 0).
		WithMetadata("wordlist", 1, time.Now()).
		Build()))
}

// streamFuzzNodes is a fixed arrival order that exercises both fuzz-class
// decisions: byte-identical bodies arriving longest path first (keep-first
// dedup keeps the first, where end-of-target dedup would evict it for the
// shorter one), a near-identical cluster bigger than the cap, distinct pages,
// and client errors the post-discovery status policy prunes.
func streamFuzzNodes() []fuzzNode {
	var nodes []fuzzNode
	for i := range 4 {
		nodes = append(nodes, fuzzNode{fmt.Sprintf("/dup/%c/deeper/path", 'a'+i), 200, "same-body"})
	}
	nodes = append(nodes, fuzzNode{"/dup", 200, "same-body"})
	pad := strings.Repeat("x", 4000)
	for i := range 14 {
		nodes = append(nodes, fuzzNode{fmt.Sprintf("/catch/%02d", 13-i), 200, fmt.Sprintf("%s-%02d", pad, i)})
	}
	for i := range 6 {
		nodes = append(nodes, fuzzNode{fmt.Sprintf("/real/%d", i), 200, strings.Repeat("real ", 20*(i+1))})
	}
	nodes = append(nodes, fuzzNode{"/missing", 404, "not found"}, fuzzNode{"/missing-too", 404, "not found"})
	return nodes
}

// batchKeepSet is the reference: one pass over the finished siteMap in node
// order, exact dedup keeping the first record per key, then the order-stable
// cluster cap over what survived.
func batchKeepSet(t *testing.T, sm *deparosstorage.SiteMap, capN int) []string {
	t.Helper()
	seen := map[hardDedupKey]struct{}{}
	var fuzz []collectedRecord
	require.NoError(t, sm.StreamAllResults(func(node *deparosstorage.DiscoveredNode) error {
		rec, _, body, ok := readDiscoveredNode(node)
		if !ok || rec.source != crawlRecordSource {
			return nil
		}
		if rec.status > 0 {
			key := fuzzDedupKey(rec, body)
			if _, dup := seen[key]; dup {
				return nil
			}
			seen[key] = struct{}{}
		}
		fuzz = append(fuzz, rec)
		return nil
	}))
	kept, _, _ := capNearIdenticalClusters(fuzz, capN)
	return keptPaths(kept)
}

// TestTargetCollector_StreamedFuzzMatchesBatch is the equivalence test: for a
// fixed arrival order, streaming the fuzz class across several flushes persists
// exactly the keep-set (and order) one batch pass over the finished siteMap
// computes, and the same keep-set as a target read once at its end.
func TestTargetCollector_StreamedFuzzMatchesBatch(t *testing.T) {
	const capN = 4
	nodes := streamFuzzNodes()

	whole := newStreamSiteMap(t)
	for _, n := range nodes {
		storeFuzzNode(t, whole, n)
	}
	want := batchKeepSet(t, whole, capN)
	require.Contains(t, want, "/dup/a/deeper/path", "keep-first keeps the first identical body")
	require.NotContains(t, want, "/dup")
	require.Contains(t, want, "/catch/13")
	require.NotContains(t, want, "/catch/09", "the fifth near-identical page is past the cap")

	// One read at the end of the target.
	singleSaver := newPathSaver()
	single := newTestDiscoverySource(singleSaver)
	single.cfg.DedupClusterCap = capN
	defer consumeItems(t, single)()
	c1 := newTargetCollector(single, "https://app.example/", whole)
	require.NoError(t, c1.finish(context.Background(), noEngineFacts{}, false))

	// The same nodes streamed across flushes that split both the dedup set and
	// the cluster.
	streamSaver := newPathSaver()
	streaming := newTestDiscoverySource(streamSaver)
	streaming.cfg.DedupClusterCap = capN
	defer consumeItems(t, streaming)()
	split := newStreamSiteMap(t)
	c2 := newTargetCollector(streaming, "https://app.example/", split)
	require.True(t, c2.streamFuzz)
	bounds := []int{0, 2, 7, 9, 16, len(nodes)}
	for i := 0; i+1 < len(bounds); i++ {
		for _, n := range nodes[bounds[i]:bounds[i+1]] {
			storeFuzzNode(t, split, n)
		}
		if i+2 < len(bounds) {
			require.NoError(t, c2.flush(context.Background()))
		}
	}
	require.Positive(t, c2.fuzzStreamed, "flushes must hand on fuzz records")
	require.NoError(t, c2.finish(context.Background(), noEngineFacts{}, false))

	assert.Equal(t, want, singleSaver.saved(crawlRecordSource))
	assert.Equal(t, want, streamSaver.saved(crawlRecordSource))

	s1, s2 := single.Stats(), streaming.Stats()
	assert.Equal(t, s1.HardDedupRemoved, s2.HardDedupRemoved)
	assert.Equal(t, 5, s2.HardDedupRemoved, "four identical bodies plus one identical 404")
	assert.Equal(t, s1.FuzzyCappedRemoved, s2.FuzzyCappedRemoved)
	assert.Equal(t, 10, s2.FuzzyCappedRemoved)
	assert.Equal(t, s1.CappedCodes, s2.CappedCodes)
	assert.Equal(t, s1.DedupedCodes, s2.DedupedCodes)
	assert.Equal(t, len(want), s2.Imported)
	assert.Equal(t, len(nodes), s2.TotalDiscovered)
}

// TestTargetCollector_KillAfterFirstFlushPersistsFuzz: the flusher persists
// the fuzz class while the crawl runs, so killing the target right after the
// first flush keeps at least that batch; the end of the target writes none of
// it twice. Streamed 4xx records keep the crawl label, so the post-discovery
// status policy (scoped to source='deparos') still prunes them.
func TestTargetCollector_KillAfterFirstFlushPersistsFuzz(t *testing.T) {
	saver := newPathSaver()
	d := newTestDiscoverySource(saver)
	d.cfg.FlushInterval = 20 * time.Millisecond
	d.cfg.DrainTimeout = time.Second
	defer consumeItems(t, d)()

	sm := newStreamSiteMap(t)
	first := []fuzzNode{
		{"/admin", 200, "admin page"},
		{"/backup", 200, "backup page"},
		{"/old", 404, "nope"},
		{"/assets", 301, ""},
	}
	for _, n := range first {
		storeFuzzNode(t, sm, n)
	}

	c := newTargetCollector(d, "https://app.example/", sm)
	ctx, kill := context.WithCancel(context.Background())
	stopFlusher := c.startFlusher(ctx)

	require.Eventually(t, func() bool {
		return len(saver.saved(crawlRecordSource)) == len(first)
	}, 5*time.Second, 5*time.Millisecond, "the first flush must persist the fuzz batch")

	// Kill the target after the first flush: those rows are already stored.
	kill()
	stopFlusher()
	persisted := saver.saved(crawlRecordSource)
	assert.GreaterOrEqual(t, len(persisted), len(first))
	assert.Contains(t, persisted, "/old", "a streamed 404 is persisted under the crawl label the 4xx cleanup filters on")

	// More lands before the engine stops, including a duplicate of a streamed
	// body, which keep-first drops without touching the streamed record.
	storeFuzzNode(t, sm, fuzzNode{"/a", 200, "admin page"})
	storeFuzzNode(t, sm, fuzzNode{"/late", 200, "late page"})
	require.NoError(t, c.finish(ctx, noEngineFacts{}, false))

	assert.Equal(t, []string{"/admin", "/backup", "/old", "/assets", "/late"}, saver.saved(crawlRecordSource))
	stats := d.Stats()
	assert.Equal(t, 6, stats.TotalDiscovered)
	assert.Equal(t, 1, stats.HardDedupRemoved)
	assert.Equal(t, 5, stats.Imported)
}

// TestTargetCollector_ClusterCapAcrossFlushes: per-cluster counts carry over
// flushes, so a near-identical flood split across three reads keeps exactly the
// first N of it in arrival order and counts every capped record.
func TestTargetCollector_ClusterCapAcrossFlushes(t *testing.T) {
	saver := newPathSaver()
	d := newTestDiscoverySource(saver)
	d.cfg.DedupClusterCap = 3
	defer consumeItems(t, d)()

	sm := newStreamSiteMap(t)
	c := newTargetCollector(d, "https://app.example/", sm)
	pad := strings.Repeat("y", 8000)
	page := func(i int) fuzzNode {
		return fuzzNode{fmt.Sprintf("/spa/%c", 'z'-i), 200, fmt.Sprintf("%s%03d", pad, i)}
	}

	i := 0
	for _, batch := range []int{2, 3, 2} {
		for range batch {
			storeFuzzNode(t, sm, page(i))
			i++
		}
		if i < 7 {
			require.NoError(t, c.flush(context.Background()))
		}
	}
	require.NoError(t, c.finish(context.Background(), noEngineFacts{}, false))

	assert.Equal(t, []string{"/spa/z", "/spa/y", "/spa/x"}, saver.saved(crawlRecordSource))
	stats := d.Stats()
	assert.Equal(t, 3, stats.ClusterCap)
	assert.Equal(t, 4, stats.FuzzyCappedRemoved)
	assert.Equal(t, 4, stats.CappedCodes[1])
	assert.Zero(t, stats.HardDedupRemoved)
}

// TestStreamsFuzz: the fuzz class streams by default, and not when
// discovery.stream_fuzz is off or in-crawl flushing is.
func TestStreamsFuzz(t *testing.T) {
	assert.True(t, DeparosDiscoveryConfig{}.streamsFuzz())
	assert.False(t, DeparosDiscoveryConfig{FuzzAtEnd: true}.streamsFuzz())
	assert.False(t, DeparosDiscoveryConfig{FlushInterval: -1}.streamsFuzz())
}
