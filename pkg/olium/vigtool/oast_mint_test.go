package vigtool

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOASTMintRequiresRepo(t *testing.T) {
	tl := NewOASTMintTool(&ScanContext{}) // Repo nil
	res, _ := tl.Execute(context.Background(), map[string]any{}, nil)
	if !res.IsError {
		t.Fatal("expected oast_mint to require a repository")
	}
}

func TestOASTMintNilContext(t *testing.T) {
	tl := NewOASTMintTool(nil)
	res, _ := tl.Execute(context.Background(), map[string]any{}, nil)
	if !res.IsError {
		t.Error("expected error with nil scan context")
	}
}

func TestOASTMintShutdownIsSafeWhenUnused(t *testing.T) {
	tl := NewOASTMintTool(&ScanContext{})
	// Never minted → no Service was created. Must not panic, and must be
	// safe to call more than once (autopilot defers it unconditionally).
	tl.Shutdown()
	tl.Shutdown()
}

func TestOASTMintToolMetadata(t *testing.T) {
	tl := NewOASTMintTool(&ScanContext{})
	if tl.Name() != "oast_mint" {
		t.Errorf("name = %q", tl.Name())
	}
	if tl.IsReadOnly() {
		t.Error("oast_mint mutates run state (starts a poller) — must not be read-only")
	}
	if _, ok := tl.Schema()["properties"]; !ok {
		t.Error("schema missing properties")
	}
}

// TestOASTMintReportsUnavailableServer: registration is asynchronous, so the
// first mint waits for it and turns a failed registration into a tool error
// that names the cause, instead of minting a canary nobody polls.
func TestOASTMintReportsUnavailableServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // nothing listens: registration is refused at once

	cfgPath := filepath.Join(t.TempDir(), "vigolium-configs.yaml")
	// fallback_to_default off: this test is ABOUT the unavailable path, and the
	// default would re-register against the public oast.pro - making the case
	// untestable and the suite reach a third party to prove it.
	cfg := "oast:\n  enabled: true\n  fallback_to_default: false\n  server_url: http://" + addr + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	tl := NewOASTMintTool(&ScanContext{Repo: newVigtoolTestRepo(t), ConfigPath: cfgPath})
	t.Cleanup(tl.Shutdown)
	start := time.Now()
	res, _ := tl.Execute(context.Background(), map[string]any{}, nil)
	if !res.IsError {
		t.Fatalf("oast_mint against an unreachable server succeeded: %s", res.Content)
	}
	if !strings.Contains(res.Content, "OAST unavailable") || !strings.Contains(res.Content, addr) {
		t.Errorf("error = %q, want it to say OAST is unavailable and name the server", res.Content)
	}
	if elapsed := time.Since(start); elapsed > oastMintReadyWait+time.Second {
		t.Errorf("oast_mint took %s, want <= %s", elapsed, oastMintReadyWait)
	}
}
