package server

import (
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
)

// These tests cover the audit-harness picker (no source path → no audit;
// explicit `audit: "off"` → audit-disabled path; explicit `piolium: <mode>` →
// piolium harness; nothing asked → no harness). Autopilot has no auto-pick:
// an installed piolium is never chosen unless the request names it. The
// swarm picker still auto-picks via `piolium.IsAvailable()`, exercised
// end-to-end via the e2e tier.

// stubHandlers builds a Handlers value just rich enough for the resolver
// methods to read settings off it. Bypasses NewHandlers' background
// goroutines.
func stubHandlers() *Handlers {
	settings := config.DefaultSettings()
	return &Handlers{settings: settings}
}

func TestResolveAutopilotAudit_NoSourceReturnsNil(t *testing.T) {
	h := stubHandlers()
	req := AgentAutopilotRequest{} // SourcePath empty
	cfg, harness := h.resolveAutopilotAuditCfgServer(req, "")
	if cfg != nil {
		t.Errorf("expected nil cfg without source, got %+v", cfg)
	}
	if harness.Name != "" {
		t.Errorf("expected zero harness without source, got %q", harness.Name)
	}
}

func TestResolveAutopilotAudit_ExplicitPioliumWinsOverDefault(t *testing.T) {
	h := stubHandlers()
	req := AgentAutopilotRequest{
		SourcePath: "/some/source",
		Piolium:    "balanced",
		// Audit omitted — explicit piolium means audit stays off.
	}
	cfg, harness := h.resolveAutopilotAuditCfgServer(req, "/some/source")
	if cfg == nil {
		t.Fatalf("expected non-nil cfg")
	}
	if cfg.Mode != "balanced" {
		t.Errorf("expected Mode=balanced, got %q", cfg.Mode)
	}
	if harness.Name != "piolium" {
		t.Errorf("expected piolium harness, got %q", harness.Name)
	}
}

func TestResolveAutopilotAudit_ExplicitAuditDriverOffPicksNothingWhenSourceMissing(t *testing.T) {
	// audit=off + no source → no audit at all; piolium stays empty.
	h := stubHandlers()
	req := AgentAutopilotRequest{Audit: "off"}
	cfg, harness := h.resolveAutopilotAuditCfgServer(req, "")
	if cfg != nil {
		t.Errorf("expected nil cfg with audit=off and no source, got %+v", cfg)
	}
	if harness.Name != "" {
		t.Errorf("expected zero harness, got %q", harness.Name)
	}
}

func TestResolveAutopilotAudit_ExplicitAuditDriverModePicksAudit(t *testing.T) {
	h := stubHandlers()
	req := AgentAutopilotRequest{
		SourcePath:      "/some/source",
		AuditDriverMode: "deep",
		// Piolium omitted — explicit audit should win even if pi is
		// available, because audit-explicit suppresses auto-pick.
	}
	cfg, harness := h.resolveAutopilotAuditCfgServer(req, "/some/source")
	if cfg == nil {
		t.Fatalf("expected non-nil cfg")
	}
	if cfg.Mode != "deep" {
		t.Errorf("expected Mode=deep, got %q", cfg.Mode)
	}
	if harness.Name != agent.DefaultAuditHarness().Name {
		t.Errorf("expected audit harness, got %q", harness.Name)
	}
}

func TestResolveSwarmAudit_OptInOnly_NoFlagsNoAudit(t *testing.T) {
	// Swarm is opt-in: empty audit AND empty piolium AND no source → nothing.
	h := stubHandlers()
	req := AgentSwarmRequest{}
	cfg, harness := h.resolveSwarmAuditCfgServer(req, "")
	if cfg != nil {
		t.Errorf("expected nil cfg, got %+v", cfg)
	}
	if harness.Name != "" {
		t.Errorf("expected zero harness, got %q", harness.Name)
	}
}

func TestResolveSwarmAudit_ExplicitPioliumOverridesAudit(t *testing.T) {
	h := stubHandlers()
	req := AgentSwarmRequest{
		SourcePath: "/some/source",
		Piolium:    "longshot",
		Audit:      "deep", // ignored when piolium is explicit
	}
	cfg, harness := h.resolveSwarmAuditCfgServer(req, "/some/source")
	if cfg == nil {
		t.Fatalf("expected non-nil cfg")
	}
	if cfg.Mode != "longshot" {
		t.Errorf("expected Mode=longshot, got %q", cfg.Mode)
	}
	if harness.Name != "piolium" {
		t.Errorf("expected piolium harness, got %q", harness.Name)
	}
}

// The nested audit harness is off unless the request asks for one: a source
// path alone, or an intensity preset, no longer starts it (CLI parity with
// `agent autopilot --audit`, default off).
func TestResolveAutopilotAudit_DefaultOff(t *testing.T) {
	h := stubHandlers()
	for _, req := range []AgentAutopilotRequest{
		{SourcePath: "/some/source"},
		{SourcePath: "/some/source", Intensity: "deep"},
		{SourcePath: "/some/source", Audit: "off", Piolium: "off"},
	} {
		if cfg, harness := h.resolveAutopilotAuditCfgServer(req, "/some/source"); cfg != nil || harness.Name != "" {
			t.Errorf("%+v: expected no audit harness, got cfg=%+v harness=%q", req, cfg, harness.Name)
		}
	}
}

func TestAutopilotAuditRequested(t *testing.T) {
	cases := []struct {
		req  AgentAutopilotRequest
		want bool
	}{
		{AgentAutopilotRequest{}, false},
		{AgentAutopilotRequest{Intensity: "deep"}, false},
		{AgentAutopilotRequest{Audit: "off"}, false},
		{AgentAutopilotRequest{Piolium: "off"}, false},
		{AgentAutopilotRequest{Audit: "deep"}, true},
		{AgentAutopilotRequest{AuditDriverMode: "lite"}, true},
		{AgentAutopilotRequest{Piolium: "balanced"}, true},
	}
	for _, tc := range cases {
		if got := autopilotAuditRequested(tc.req); got != tc.want {
			t.Errorf("autopilotAuditRequested(%+v) = %v, want %v", tc.req, got, tc.want)
		}
	}
}
