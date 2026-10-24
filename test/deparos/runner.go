//go:build integration

package integration_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	deparosconfig "github.com/vigolium/vigolium/pkg/deparos/config"
	"github.com/vigolium/vigolium/pkg/deparos/discovery"
	"github.com/vigolium/vigolium/pkg/deparos/storage"
)

// TestOptions are the knobs the integration tests turn on a deparos run.
type TestOptions struct {
	StartURL      string
	ScopeMode     string // any | subdomain | exact
	ObservedPaths bool
	Threads       int
	HTTPTimeout   int // seconds
}

// NewTestOptions returns spider-only options for startURL: no wordlists, so
// every result was reached by following the test server's own content.
func NewTestOptions(startURL string) *TestOptions {
	return &TestOptions{
		StartURL:    startURL,
		ScopeMode:   "subdomain",
		Threads:     4,
		HTTPTimeout: 10,
	}
}

// RunDeparos runs a discovery engine against opts.StartURL on a fresh
// in-memory sitemap and returns everything it stored.
func RunDeparos(t *testing.T, ctx context.Context, opts *TestOptions) *RunResult {
	t.Helper()

	cfg := deparosconfig.NewDefaultConfig()
	cfg.Target.StartURL = opts.StartURL
	cfg.Target.ScopeMode = opts.ScopeMode
	cfg.Filenames.UseObservedPaths = opts.ObservedPaths
	cfg.Engine.DiscoveryThreads = opts.Threads
	cfg.Engine.Timeout = time.Duration(opts.HTTPTimeout) * time.Second
	// Spider-only: no guessed extensions or backup names, so result counts
	// reflect what the server's content links to.
	cfg.Extensions.TestCustom = false
	cfg.Extensions.TestBackupExtensions = false
	cfg.Extensions.JSBundleSweep = false
	cfg.Sitemap.Enabled = false

	siteMap, err := storage.NewSiteMap(storage.DefaultConfig())
	if err != nil {
		t.Fatalf("create sitemap: %v", err)
	}
	defer func() { _ = siteMap.Close() }()

	engine, err := discovery.NewEngineWithContext(ctx, cfg, siteMap)
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}
	if err := engine.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	_ = engine.WaitForQueues(ctx)
	engine.Stop()

	var results []JSONResult
	err = siteMap.StreamAllResults(func(node *storage.DiscoveredNode) error {
		results = append(results, nodeToJSONResult(node))
		return nil
	})
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("stream results: %v", err)
	}
	return &RunResult{Results: results, Count: len(results)}
}

func nodeToJSONResult(node *storage.DiscoveredNode) JSONResult {
	r := JSONResult{URL: node.URL().String(), Tags: node.Tags(), Type: "file"}
	if node.IsDirectory() {
		r.Type = "directory"
	}
	if req := node.Request(); req != nil {
		r.Method = req.Method
	}
	if resp := node.Response(); resp != nil {
		r.StatusCode = resp.StatusCode
		r.ContentType = resp.MIMEType
		r.ContentLength = int(resp.ContentLength)
		r.Location = resp.Location
		r.Title = resp.Title
		r.Headers = resp.Headers
	}
	if meta := node.Metadata(); meta != nil {
		r.FoundBy = meta.FoundBy
		r.Depth = int(meta.Depth)
		if !meta.Timestamp.IsZero() {
			r.Timestamp = meta.Timestamp.Format(time.RFC3339)
		}
	}
	return r
}
