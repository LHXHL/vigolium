package source

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/discovery"
	deparosstorage "github.com/vigolium/vigolium/pkg/deparos/storage"
)

// noEngineFacts stands in for the engine at the end of a target.
type noEngineFacts struct{}

func (noEngineFacts) RequestTemplateOutcomes() []discovery.TemplateOutcome { return nil }
func (noEngineFacts) JSFactBundles() []discovery.JSFactBundle              { return nil }
func (noEngineFacts) SitemapCapped() int                                   { return 0 }

func newStreamSiteMap(t *testing.T) *deparosstorage.SiteMap {
	t.Helper()
	cfg := deparosstorage.DefaultConfig()
	cfg.SaveResponseBody = true // as discovery runs it by default; dedup hashes bodies
	sm, err := deparosstorage.NewSiteMap(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })
	return sm
}

// storeNode writes one discovered node with the given provenance.
func storeNode(t *testing.T, sm *deparosstorage.SiteMap, rawURL, foundBy, method, ctype string, body []byte) {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	require.NoError(t, sm.Store(deparosstorage.NewResultBuilder().
		WithURL(u).
		WithRequest(method, nil, nil).
		WithResponse(200, map[string]string{"Content-Type": ctype}, body, int64(len(body)), ctype, "", "", 0, 0).
		WithMetadata(foundBy, 1, time.Now()).
		Build()))
}

// consumeItems consumes work items until stop closes.
func consumeItems(t *testing.T, d *DeparosDiscoverySource) (stop func()) {
	t.Helper()
	quit := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		for {
			select {
			case <-d.items:
			case <-quit:
				return
			}
		}
	}()
	return func() { close(quit); <-exited }
}

// TestTargetCollector_FlushPersistsReferencedBeforeKill: a flush persists the
// referenced class while the crawl runs, so killing the target right after it
// loses none of those rows; with discovery.stream_fuzz off the fuzz class waits
// for the end, and the end of the target does not write a streamed row twice.
func TestTargetCollector_FlushPersistsReferencedBeforeKill(t *testing.T) {
	saver := newCaptureSaver()
	d := newTestDiscoverySource(saver)
	d.cfg.FlushInterval = 20 * time.Millisecond
	d.cfg.FuzzAtEnd = true
	d.cfg.DrainTimeout = time.Second
	defer consumeItems(t, d)()

	sm := newStreamSiteMap(t)
	for i := 0; i < 3; i++ {
		storeNode(t, sm, fmt.Sprintf("https://app.example/form/%d", i), "form", "POST", "text/html", []byte(fmt.Sprintf("form-%d", i)))
	}
	for i := 0; i < 2; i++ {
		storeNode(t, sm, fmt.Sprintf("https://app.example/api/%d", i), "js-extracted", "GET", "application/json", []byte(fmt.Sprintf(`{"api":%d}`, i)))
	}
	for i := 0; i < 4; i++ {
		storeNode(t, sm, fmt.Sprintf("https://app.example/fuzz/%d", i), "wordlist", "GET", "text/html", []byte(fmt.Sprintf("page-%d", i)))
	}

	c := newTargetCollector(d, "https://app.example/", sm)
	ctx, kill := context.WithCancel(context.Background())
	stopFlusher := c.startFlusher(ctx)

	require.Eventually(t, func() bool {
		saver.mu.Lock()
		defer saver.mu.Unlock()
		return saver.bySource[formRecordSource] == 3 && saver.bySource[jstangleRecordSource] == 2
	}, 5*time.Second, 5*time.Millisecond, "the first flush must persist the referenced class")

	// Kill the target after the first flush.
	kill()
	stopFlusher()

	saver.mu.Lock()
	assert.Zero(t, saver.bySource[crawlRecordSource], "the fuzz class is not streamed")
	saver.mu.Unlock()

	// One more referenced node lands before the engine stops.
	storeNode(t, sm, "https://app.example/form/late", "form", "POST", "text/html", []byte("late"))

	require.NoError(t, c.finish(ctx, noEngineFacts{}, false))

	saver.mu.Lock()
	defer saver.mu.Unlock()
	assert.Equal(t, 4, saver.bySource[formRecordSource], "streamed forms are not persisted again; the late one is")
	assert.Equal(t, 2, saver.bySource[jstangleRecordSource])
	assert.Equal(t, 4, saver.bySource[crawlRecordSource], "the fuzz class is persisted at the end")

	stats := d.Stats()
	assert.Equal(t, 10, stats.TotalDiscovered)
	assert.Equal(t, 10, stats.Imported, "streamed and final imports are both counted")
	assert.Zero(t, stats.HardDedupRemoved)
}

// TestTargetCollector_StreamingDisabledLeavesEverythingToTheEnd: a negative
// flush interval turns the flusher off.
func TestTargetCollector_StreamingDisabledLeavesEverythingToTheEnd(t *testing.T) {
	saver := newCaptureSaver()
	d := newTestDiscoverySource(saver)
	d.cfg.FlushInterval = -1
	defer consumeItems(t, d)()

	sm := newStreamSiteMap(t)
	storeNode(t, sm, "https://app.example/form", "form", "POST", "text/html", []byte("form"))
	c := newTargetCollector(d, "https://app.example/", sm)

	stop := c.startFlusher(context.Background())
	time.Sleep(50 * time.Millisecond)
	stop()
	saver.mu.Lock()
	assert.Zero(t, saver.bySource[formRecordSource])
	saver.mu.Unlock()

	require.NoError(t, c.finish(context.Background(), noEngineFacts{}, false))
	saver.mu.Lock()
	defer saver.mu.Unlock()
	assert.Equal(t, 1, saver.bySource[formRecordSource])
}

// TestTargetCollector_SpecEndpointsStreamedOnce: an API spec read by a flush is
// parsed and its endpoints persisted then, and not again at the end.
func TestTargetCollector_SpecEndpointsStreamedOnce(t *testing.T) {
	saver := newCaptureSaver()
	d := newTestDiscoverySource(saver)
	defer consumeItems(t, d)()

	sm := newStreamSiteMap(t)
	storeNode(t, sm, "https://api.example.com/spec", "wordlist", "GET", "text/yaml", minimalSpec)
	c := newTargetCollector(d, "https://api.example.com/", sm)

	require.NoError(t, c.flush(context.Background()))
	saver.mu.Lock()
	streamed := saver.bySource[specRecordSource]
	saver.mu.Unlock()
	require.Positive(t, streamed, "the flush must ingest the spec's endpoints")

	require.NoError(t, c.finish(context.Background(), noEngineFacts{}, false))
	saver.mu.Lock()
	defer saver.mu.Unlock()
	assert.Equal(t, streamed, saver.bySource[specRecordSource], "the end of the target must not ingest the spec again")
	assert.Equal(t, 1, saver.bySource[crawlRecordSource], "the spec document itself is a fuzz-class record")
}

// TestTargetCollector_SplitReadMatchesSingleRead: in end-of-target mode
// (discovery.stream_fuzz off), reading a siteMap in batches (dedup state
// carried across reads) keeps exactly the fuzz records one read of the finished
// siteMap keeps, cluster cap included, and exact dedup still keeps the shorter
// path. Streaming mode's equivalent is TestTargetCollector_StreamedFuzzMatchesBatch.
func TestTargetCollector_SplitReadMatchesSingleRead(t *testing.T) {
	type node struct{ path, body string }
	var nodes []node
	// Byte-identical bodies on paths of different lengths (exact dedup keeps
	// the shorter), arriving longest-first so the eviction crosses batches.
	for i := 0; i < 4; i++ {
		nodes = append(nodes, node{fmt.Sprintf("/dup/%s", string(rune('a'+i))+"/deeper/path"), "same-body"})
	}
	nodes = append(nodes, node{"/dup", "same-body"})
	// A near-identical cluster bigger than the cap.
	for i := 0; i < 14; i++ {
		nodes = append(nodes, node{fmt.Sprintf("/catch/%02d", i), fmt.Sprintf("%s-%02d", string(make([]byte, 4000)), i)})
	}
	for i := 0; i < 6; i++ {
		nodes = append(nodes, node{fmt.Sprintf("/real/%d", i), fmt.Sprintf("distinct body number %d", i)})
	}

	keptPaths := func(c *targetCollector) []string {
		var fuzz []collectedRecord
		for _, rec := range c.fuzz {
			if rec.rr != nil {
				fuzz = append(fuzz, rec)
			}
		}
		sortShortestPathFirst(fuzz)
		fuzz, _, _ = capNearIdenticalClusters(fuzz, defaultDedupClusterCap)
		paths := make([]string, 0, len(fuzz))
		for _, rec := range fuzz {
			paths = append(paths, rec.path)
		}
		sort.Strings(paths)
		return paths
	}
	store := func(sm *deparosstorage.SiteMap, from, to int) {
		for _, n := range nodes[from:to] {
			storeNode(t, sm, "https://app.example"+n.path, "wordlist", "GET", "text/html", []byte(n.body))
		}
	}

	d := newTestDiscoverySource(newCaptureSaver())
	d.cfg.FuzzAtEnd = true

	whole := newStreamSiteMap(t)
	store(whole, 0, len(nodes))
	single := newTargetCollector(d, "https://app.example/", whole)
	require.NoError(t, single.collect())

	split := newStreamSiteMap(t)
	batched := newTargetCollector(d, "https://app.example/", split)
	for _, bounds := range [][2]int{{0, 3}, {3, 9}, {9, len(nodes)}} {
		store(split, bounds[0], bounds[1])
		require.NoError(t, batched.collect())
	}

	assert.Equal(t, keptPaths(single), keptPaths(batched))
	assert.Equal(t, single.stats.DedupedCodes, batched.stats.DedupedCodes)
	assert.Contains(t, keptPaths(batched), "/dup", "exact dedup keeps the shortest path across batches")
}
