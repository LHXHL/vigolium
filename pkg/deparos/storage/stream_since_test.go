package storage

import (
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestStreamResultsSinceResumesWithoutLossOrRepeat drives the cursor the way a
// discovery flusher does: read what landed, store more, resume from the returned
// id. Every node must come back exactly once across the reads, page boundaries
// included.
func TestStreamResultsSinceResumesWithoutLossOrRepeat(t *testing.T) {
	sm := newTestSiteMap(t)
	require.Zero(t, sm.LatestNodeID(), "an empty sitemap has no nodes")

	first := storeNodes(t, sm, walkPageSize+10)

	seen := map[string]int{}
	collect := func(node *DiscoveredNode) error {
		seen[node.URL().String()]++
		return nil
	}

	cursor, err := sm.StreamResultsSince(0, collect)
	require.NoError(t, err)
	require.Equal(t, sm.LatestNodeID(), cursor, "the cursor ends at the newest row")
	require.Len(t, seen, len(first))

	// Nothing new: the cursor stays put and nothing is re-read.
	again, err := sm.StreamResultsSince(cursor, collect)
	require.NoError(t, err)
	require.Equal(t, cursor, again)

	// A second batch lands while the "crawl" is still running.
	at := time.Now()
	for i := 0; i < 25; i++ {
		u, perr := url.Parse(fmt.Sprintf("https://example.com/later/%02d", i))
		require.NoError(t, perr)
		require.NoError(t, sm.Store(NewResultBuilder().
			WithURL(u).
			WithRequest("GET", nil, nil).
			WithResponse(200, nil, []byte(fmt.Sprintf("later-%02d", i)), 8, "text/plain", "", "", 0, 0).
			WithMetadata("wordlist", 1, at).
			Build()))
	}
	cursor, err = sm.StreamResultsSince(cursor, collect)
	require.NoError(t, err)
	require.Equal(t, sm.LatestNodeID(), cursor)

	require.Len(t, seen, len(first)+25)
	for u, n := range seen {
		require.Equalf(t, 1, n, "%s was read %d times", u, n)
	}
}

// TestStreamResultsSinceStopsAtFailingRow: a callback error returns the cursor
// of the last row fully handled, so a retry resumes at the failing row.
func TestStreamResultsSinceStopsAtFailingRow(t *testing.T) {
	sm := newTestSiteMap(t)
	urls := storeNodes(t, sm, 5)

	boom := errors.New("boom")
	var handled []string
	cursor, err := sm.StreamResultsSince(0, func(node *DiscoveredNode) error {
		if len(handled) == 2 {
			return boom
		}
		handled = append(handled, node.URL().String())
		return nil
	})
	require.ErrorIs(t, err, boom)
	require.Equal(t, urls[:2], handled)

	var rest []string
	_, err = sm.StreamResultsSince(cursor, func(node *DiscoveredNode) error {
		rest = append(rest, node.URL().String())
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, urls[2:], rest, "the retry resumes at the row that failed")
}
