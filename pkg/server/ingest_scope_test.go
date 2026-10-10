package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func ingestScopeRequest(t *testing.T, rawURL string) *httpmsg.HttpRequestResponse {
	t.Helper()
	rr, err := httpmsg.GetRawRequestFromURL(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

// The ingest scope of a project with a config overlay is the server's scope
// with the overlay applied; a project without one shares the global matcher;
// an overlay change or a scope reload rebuilds it; a broken overlay refuses.
func TestIngestScopeForProjectOverlay(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writeServerProjectOverlay(t, overlayProjectA,
		"scope:\n  applied_on_ingest: true\n  host:\n    include: [\"a.example.com\"]\n")
	h := &Handlers{settings: config.DefaultSettings()}

	in := ingestScopeRequest(t, "http://a.example.com/x")
	out := ingestScopeRequest(t, "http://b.example.com/x")

	if !h.isIngestInScope(in, overlayProjectA) || h.isIngestInScope(out, overlayProjectA) {
		t.Fatal("project A: the overlay's host include must decide")
	}
	if !h.isIngestInScope(out, overlayProjectB) || !h.isIngestInScope(out, database.DefaultProjectUUID) {
		t.Fatal("projects without an overlay keep the global scope")
	}

	// The overlay changes on disk (CLI `scope set --project`): next record sees it.
	time.Sleep(10 * time.Millisecond)
	writeServerProjectOverlay(t, overlayProjectA,
		"scope:\n  applied_on_ingest: true\n  host:\n    include: [\"b.example.com\", \"other.example.com\"]\n")
	if h.isIngestInScope(in, overlayProjectA) || !h.isIngestInScope(out, overlayProjectA) {
		t.Fatal("project A: an edited overlay must replace the cached scope")
	}

	// A scope hot reload invalidates every cached project scope.
	h.resetScopeMatcher()
	if len(h.projectScopes) != 0 {
		t.Fatal("resetScopeMatcher must drop cached project scopes")
	}

	writeServerProjectOverlay(t, overlayProjectB, "scope: [\n")
	if h.isIngestInScope(out, overlayProjectB) {
		t.Fatal("a broken overlay must refuse, not fall back to the global scope")
	}
}

// The ingest proxy judges what it records by the scope of the project it
// records into (the default project), overlay included.
func TestIngestProxyAppliesProjectOverlay(t *testing.T) {
	if testing.Short() {
		t.Skip("spins up listeners")
	}
	t.Setenv("HOME", t.TempDir())
	writeServerProjectOverlay(t, database.DefaultProjectUUID,
		"scope:\n  applied_on_ingest: true\n  host:\n    include: [\"127.0.0.1\"]\n")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}))
	defer upstream.Close()

	ctx := context.Background()
	db, repo := newPinnedTestDB(t)
	if err := repo.CreateProject(ctx, &database.Project{
		UUID: database.DefaultProjectUUID, Name: "default", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create project: %v", err)
	}
	h := &Handlers{settings: config.DefaultSettings()}
	proxySrv := newIngestProxy("127.0.0.1:0", db, repo, nil, h.settings, h.ingestScopeFor, nil, false, nil)
	pu, err := url.Parse(startProxy(t, proxySrv))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	get := func(path string) {
		t.Helper()
		resp, err := client.Get(upstream.URL + path)
		if err != nil {
			t.Fatalf("GET via proxy: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(body) != "hello" {
			t.Fatalf("the proxy forwards whatever scope says; got %q", body)
		}
	}

	get("/admitted")
	if waitForHostRecord(t, ctx, repo, "127.0.0.1") == nil {
		t.Fatal("an in-scope transaction was not recorded")
	}

	// The overlay now excludes the upstream: the next transaction is
	// forwarded but not recorded.
	time.Sleep(10 * time.Millisecond)
	writeServerProjectOverlay(t, database.DefaultProjectUUID,
		"scope:\n  applied_on_ingest: true\n  host:\n    include: [\"in-scope.example\"]\n")
	get("/refused")
	time.Sleep(300 * time.Millisecond)
	recs, err := repo.GetRecordsByHostname(ctx, database.DefaultProjectUUID, "127.0.0.1", 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if strings.Contains(r.URL, "/refused") {
			t.Fatalf("recorded an out-of-scope transaction: %s", r.URL)
		}
	}
	if len(recs) != 1 {
		t.Fatalf("records = %d, want only the admitted one", len(recs))
	}
}
