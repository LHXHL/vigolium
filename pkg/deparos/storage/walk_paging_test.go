package storage

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// storeNodes writes n result nodes with distinct URLs. They share a discovered_at
// second on purpose: that is the tie case the keyset cursor has to survive, and
// it is what a real crawl produces (many nodes found in the same second).
func storeNodes(t *testing.T, sm *SiteMap, n int) []string {
	t.Helper()
	at := time.Now()
	urls := make([]string, n)
	for i := 0; i < n; i++ {
		raw := fmt.Sprintf("https://example.com/page/%04d", i)
		urls[i] = raw
		u, err := url.Parse(raw)
		require.NoError(t, err)
		result := NewResultBuilder().
			WithURL(u).
			WithRequest("GET", nil, nil).
			WithResponse(200, nil, []byte(fmt.Sprintf("body-%04d", i)), 9, "text/plain", "", "", 0, 0).
			WithMetadata("wordlist", 1, at).
			Build()
		require.NoError(t, sm.Store(result))
	}
	return urls
}

// TestWalkersPageWithoutLossOrRepeat is the regression test for the walkers
// turning into real pagination. They used to Scan an entire selection into a
// slice before the first callback; now they fetch bounded pages. Crossing
// several page boundaries must return every node exactly once.
func TestWalkersPageWithoutLossOrRepeat(t *testing.T) {
	// Comfortably more than walkPageSize, so several boundaries are crossed.
	const n = walkPageSize*2 + 37

	sm := newTestSiteMap(t)
	want := storeNodes(t, sm, n)

	check := func(t *testing.T, name string, seen []string) {
		t.Helper()
		if len(seen) != len(want) {
			t.Fatalf("%s returned %d nodes, want %d", name, len(seen), len(want))
		}
		counts := make(map[string]int, len(seen))
		for _, u := range seen {
			counts[u]++
		}
		for _, u := range want {
			switch counts[u] {
			case 1:
			case 0:
				t.Errorf("%s: %q was skipped at a page boundary", name, u)
			default:
				t.Errorf("%s: %q returned %d times at a page boundary", name, u, counts[u])
			}
		}
	}

	t.Run("StreamAllResults", func(t *testing.T) {
		var seen []string
		require.NoError(t, sm.StreamAllResults(func(node *DiscoveredNode) error {
			seen = append(seen, node.URL().String())
			return nil
		}))
		check(t, "StreamAllResults", seen)
	})

	t.Run("WalkAllNodes", func(t *testing.T) {
		var seen []string
		require.NoError(t, sm.repo.WalkAllNodes(context.Background(), func(m *NodeModel) error {
			seen = append(seen, m.URL)
			return nil
		}))
		check(t, "WalkAllNodes", seen)
	})
}

// TestWalkerCallbackErrorStopsIteration keeps the early-stop contract: a callback
// returning an error ends the walk immediately, including mid-page.
func TestWalkerCallbackErrorStopsIteration(t *testing.T) {
	sm := newTestSiteMap(t)
	storeNodes(t, sm, walkPageSize+10)

	stopAfter := 3
	count := 0
	wantErr := fmt.Errorf("stop here")
	err := sm.StreamAllResults(func(*DiscoveredNode) error {
		count++
		if count == stopAfter {
			return wantErr
		}
		return nil
	})
	require.ErrorIs(t, err, wantErr)
	require.Equal(t, stopAfter, count, "walk kept going after the callback asked it to stop")
}

// TestWalkersOnEmptyStore covers the zero-row path, where a paged walker must
// return immediately rather than loop.
func TestWalkersOnEmptyStore(t *testing.T) {
	sm := newTestSiteMap(t)

	calls := 0
	require.NoError(t, sm.StreamAllResults(func(*DiscoveredNode) error {
		calls++
		return nil
	}))
	require.Zero(t, calls)

	require.NoError(t, sm.repo.WalkAllNodes(context.Background(), func(*NodeModel) error {
		calls++
		return nil
	}))
	require.Zero(t, calls)
}

// TestWalkNodesFilteredBySessionPages covers the session-filtered raw-SQL variant,
// which pages through a different statement than the model query.
func TestWalkNodesFilteredBySessionPages(t *testing.T) {
	sm := newTestSiteMap(t)
	const n = walkPageSize + 25
	want := storeNodes(t, sm, n)

	seen := make(map[string]int, n)
	require.NoError(t, sm.StreamResultsBySessionName(sm.SessionName(), func(node *DiscoveredNode) error {
		seen[node.URL().String()]++
		return nil
	}))

	require.Len(t, seen, len(want), "session-filtered walk returned the wrong number of distinct nodes")
	for _, u := range want {
		require.Equal(t, 1, seen[u], "node %q was skipped or repeated across a page boundary", u)
	}
}

// TestWalkersReturnNodesWithUnsetDiscoveredAt pins the keyset FLOOR.
//
// A result built without WithMetadata stores discovered_at from a zero
// time.Time — a large negative Unix value, not 0. A starting cursor of 0
// therefore sorts ABOVE such rows and drops them from every walk. The bug is
// invisible to a fixture that always sets a timestamp, and invisible to any
// single-page walk written before the cursor existed.
func TestWalkersReturnNodesWithUnsetDiscoveredAt(t *testing.T) {
	sm := newTestSiteMap(t)

	u, err := url.Parse("https://example.com/no-metadata")
	require.NoError(t, err)
	// No WithMetadata: discovered_at is left unset on purpose.
	require.NoError(t, sm.Store(NewResultBuilder().
		WithURL(u).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("body"), 4, "text/plain", "", "", 0, 0).
		Build()))

	var seen []string
	require.NoError(t, sm.StreamAllResults(func(node *DiscoveredNode) error {
		seen = append(seen, node.URL().String())
		return nil
	}))
	require.Len(t, seen, 1, "a node with an unset discovered_at was dropped by the keyset floor")

	var walked int
	require.NoError(t, sm.repo.WalkAllNodes(context.Background(), func(*NodeModel) error {
		walked++
		return nil
	}))
	require.Equal(t, 1, walked, "WalkAllNodes dropped a node with an unset depth/discovered_at")
}
