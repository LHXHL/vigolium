package cli

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
)

// agentPreflightFlags backs --preflight-timeout / --no-preflight on the agent
// commands that ping the provider before working (query, triage, swarm,
// autopilot). `agent audit` has its own pair with the same names, which
// bounds its drivers' preflights instead.
type agentPreflightFlags struct {
	timeout time.Duration
	skip    bool
}

// registerAgentPreflightFlags adds the pair to cmd.
func registerAgentPreflightFlags(cmd *cobra.Command, f *agentPreflightFlags) {
	fs := cmd.Flags()
	fs.DurationVar(&f.timeout, "preflight-timeout", 0, "Deadline of the provider preflight ping (0 = agent.olium.preflight_timeout, default 15s; 60s for a local Ollama/LM Studio endpoint)")
	fs.BoolVar(&f.skip, "no-preflight", false, "Skip the provider preflight ping (a missing or broken provider then fails on the first real call)")
}

// apply folds --preflight-timeout into the loaded settings, where
// Engine.Preflight reads it (OliumConfig.EffectivePreflightTimeout).
func (f *agentPreflightFlags) apply(settings *config.Settings) {
	if f == nil || settings == nil || f.timeout <= 0 {
		return
	}
	settings.Agent.Olium.PreflightTimeout = f.timeout.String()
}

// validateAgentBudgets rejects negative --max-commands / --token-budget /
// --max-cost-usd (0 means no cap, or the preset).
func validateAgentBudgets(maxCommands int, tokenBudget int64, maxCostUSD float64) error {
	switch {
	case maxCommands < 0:
		return usageErrorf("--max-commands must be >= 0, got %d", maxCommands)
	case tokenBudget < 0:
		return usageErrorf("--token-budget must be >= 0, got %d", tokenBudget)
	case maxCostUSD < 0:
		return usageErrorf("--max-cost-usd must be >= 0, got %g", maxCostUSD)
	}
	return nil
}
