package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
)

// `agent swarm` launches a nested coding-agent CLI (vigolium-audit → claude,
// piolium → pi) only when --audit / --piolium (or the prompt) asks for one.

func TestSwarmAuditFlagsDefaultOff(t *testing.T) {
	audit := agentSwarmCmd.Flags().Lookup("audit")
	require.NotNil(t, audit)
	assert.Equal(t, "off", audit.DefValue, "--audit must default off")
	assert.Equal(t, "lite", audit.NoOptDefVal, "bare --audit means lite")

	pio := agentSwarmCmd.Flags().Lookup("piolium")
	require.NotNil(t, pio)
	assert.Equal(t, "", pio.DefValue, "--piolium must default empty (off)")
}

func TestResolveSwarmAuditHarness(t *testing.T) {
	settingsAudit := config.DefaultSettings().Agent.Audit
	const src = "/some/source"

	t.Run("default off with source", func(t *testing.T) {
		for _, tc := range []struct{ audit, pio string }{{"off", ""}, {"", ""}, {"off", "off"}} {
			cfg, harness, doc := resolveSwarmAuditHarness(tc.audit, tc.pio, src, settingsAudit)
			assert.Nil(t, cfg, "%+v", tc)
			assert.Empty(t, harness.Name, "%+v", tc)
			assert.Equal(t, &agentAuditHarness{Mode: "off"}, doc, "%+v", tc)
		}
	})

	t.Run("explicit audit without source runs nothing", func(t *testing.T) {
		cfg, _, doc := resolveSwarmAuditHarness("lite", "", "", settingsAudit)
		assert.Nil(t, cfg)
		assert.Equal(t, "lite", doc.Mode)
		assert.Empty(t, doc.Harness)
		assert.Empty(t, doc.AgentCLI)
	})

	t.Run("explicit audit", func(t *testing.T) {
		cfg, harness, doc := resolveSwarmAuditHarness("deep", "", src, settingsAudit)
		require.NotNil(t, cfg)
		assert.Equal(t, "deep", cfg.Mode)
		assert.Equal(t, agent.DefaultAuditHarness().Name, harness.Name)
		assert.Equal(t, &agentAuditHarness{Mode: "deep", Harness: harness.Name, AgentCLI: "claude"}, doc)
	})

	t.Run("explicit piolium", func(t *testing.T) {
		cfg, harness, doc := resolveSwarmAuditHarness("off", "balanced", src, settingsAudit)
		require.NotNil(t, cfg)
		assert.Equal(t, "balanced", cfg.Mode)
		assert.Equal(t, "piolium", harness.Name)
		assert.Equal(t, &agentAuditHarness{Mode: "off", Piolium: "balanced", Harness: "piolium", AgentCLI: "pi"}, doc)
	})
}

// The prompt can ask for a harness, but an explicit flag wins over it.
func TestApplyIntentToSwarmFlagsAudit(t *testing.T) {
	prevAudit, prevPio := swarmAudit, swarmPiolium
	prevTarget, prevSource, prevApplied := swarmTarget, swarmSource, swarmIntentApplied
	t.Cleanup(func() {
		swarmAudit, swarmPiolium = prevAudit, prevPio
		swarmTarget, swarmSource, swarmIntentApplied = prevTarget, prevSource, prevApplied
		for _, name := range []string{"audit", "piolium"} {
			f := agentSwarmCmd.Flags().Lookup(name)
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		}
	})

	swarmAudit, swarmPiolium = "off", ""
	applyIntentToSwarmFlags(agentSwarmCmd, agent.AppIntent{SourcePath: "/src"})
	assert.Equal(t, "off", swarmAudit, "a prompt that does not ask keeps audit off")
	assert.Empty(t, swarmPiolium)

	applyIntentToSwarmFlags(agentSwarmCmd, agent.AppIntent{SourcePath: "/src", Audit: "balanced"})
	assert.Equal(t, "balanced", swarmAudit, "a prompt that asks turns audit on")

	swarmAudit = "off"
	require.NoError(t, agentSwarmCmd.Flags().Set("audit", "off"))
	applyIntentToSwarmFlags(agentSwarmCmd, agent.AppIntent{SourcePath: "/src", Audit: "deep", Piolium: "lite"})
	assert.Equal(t, "off", swarmAudit, "explicit --audit off wins over the prompt")
	assert.Equal(t, "lite", swarmPiolium)
}

// The swarm run document echoes the harness choice.
func TestSwarmRunDocumentEchoesAuditHarness(t *testing.T) {
	withAgentJSONOutput(t)
	_, _, harness := resolveSwarmAuditHarness("lite", "", "/some/source", config.DefaultSettings().Agent.Audit)
	out := captureStdout(t, func() {
		_ = emitAgentRunDocument(&agentRunOutcome{
			Command:         "agent swarm",
			Mode:            "swarm",
			AgenticScanUUID: "run-1",
			End:             database.AgenticRunEnd{},
			AuditHarness:    harness,
		})
	})
	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(out)), &doc))
	assert.Equal(t, map[string]any{"mode": "lite", "harness": "audit", "agent_cli": "claude"}, doc["audit_harness"])
}
