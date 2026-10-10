package database

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// saveRouteFacts stores a JS record on host for project, stamps scanUUID on
// it, and anchors a jstangle-facts artifact with body on it.
func saveRouteFacts(t *testing.T, repo *Repository, host, project, scanUUID, body string) {
	t.Helper()
	ctx := context.Background()
	rr, err := httpmsg.ParseRawRequest("GET /app.js HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	rr = rr.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n" + host)))
	uuid, err := repo.SaveRecord(ctx, rr, "test", project)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.NewUpdate().Table("http_records").Set("scan_uuid = ?", scanUUID).Where("uuid = ?", uuid).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(body))
	if err := repo.SaveAnalysisArtifactForRecord(ctx, &AnalysisArtifact{
		HTTPRecordUUID: uuid, Kind: JSFactsArtifactKind, SHA256: fmt.Sprintf("%x", digest), Content: []byte(body),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestListClientRoutesScopesByProjectScanAndHost(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	ctx := context.Background()

	saveRouteFacts(t, repo, "app.test", DefaultProjectUUID, "scan-1", `{"source_url":"http://app.test/app.js","clientRoute":[
		{"kind":"clientRoute","path":{"rendered":":reportId"},"fullPath":{"rendered":"/admin/reports/:reportId","static":true},"routeType":"page","provenance":{"extractor":"router-config","confidence":"high"}},
		{"kind":"clientRoute","path":{"rendered":"/old"},"routeType":"redirect","provenance":{"extractor":"router-config","confidence":"high"}},
		{"kind":"clientRoute","path":{"rendered":":reportId"},"fullPath":{"rendered":"/admin/reports/:reportId","static":true},"routeType":"page","provenance":{"extractor":"router-config","confidence":"high"}}
	]}`)
	saveRouteFacts(t, repo, "other.test", DefaultProjectUUID, "scan-2", `{"source_url":"http://other.test/app.js","clientRoute":[
		{"kind":"clientRoute","path":{"rendered":"/settings"},"routeType":"page","provenance":{"extractor":"react-router-jsx","confidence":"high"}}
	]}`)
	saveRouteFacts(t, repo, "app.test", "other-project", "scan-3", `{"source_url":"http://app.test/app.js","clientRoute":[
		{"kind":"clientRoute","path":{"rendered":"/leak"},"routeType":"page","provenance":{"extractor":"react-router-jsx","confidence":"high"}}
	]}`)

	all, err := repo.ListClientRoutes(ctx, "", DefaultProjectUUID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Duplicate route in one bundle collapses; the redirect is returned as
	// declared (filtering is the caller's); the other project's never leaks.
	if len(all) != 3 {
		t.Fatalf("project routes = %+v, want 3", all)
	}
	first := all[0]
	if first.Hostname != "app.test" || first.Scheme != "https" || first.Port != 443 || first.FullPath != "/admin/reports/:reportId" ||
		!first.FullPathStatic || first.Extractor != "router-config" || first.ScanUUID != "scan-1" || first.SourceURL != "http://app.test/app.js" {
		t.Errorf("first route = %+v", first)
	}
	for _, r := range all {
		if r.Path == "/leak" {
			t.Fatal("route from another project returned")
		}
	}

	byScan, err := repo.ListClientRoutes(ctx, "scan-2", DefaultProjectUUID, nil, 0)
	if err != nil || len(byScan) != 1 || byScan[0].Path != "/settings" {
		t.Fatalf("scan-2 routes = %+v, %v", byScan, err)
	}

	byHost, err := repo.ListClientRoutes(ctx, "", DefaultProjectUUID, []HostTarget{{Scheme: "https", Hostname: "other.test", Port: 443}}, 0)
	if err != nil || len(byHost) != 1 || byHost[0].Hostname != "other.test" {
		t.Fatalf("other.test routes = %+v, %v", byHost, err)
	}

	capped, err := repo.ListClientRoutes(ctx, "", DefaultProjectUUID, nil, 1)
	if err != nil || len(capped) != 1 {
		t.Fatalf("limit 1 = %+v, %v", capped, err)
	}
}
