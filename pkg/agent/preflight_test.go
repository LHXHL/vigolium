package agent

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/apicontract"
)

// blockingRuntime answers NewSession per newErr and blocks RunOnSession until
// its ctx ends — a provider that never replies.
type blockingRuntime struct {
	fakeRuntime
	newErr error
}

func (b *blockingRuntime) NewSession(_ *config.OliumConfig, _ string) (AgentSession, error) {
	if b.newErr != nil {
		return nil, b.newErr
	}
	return fakeSession{}, nil
}

func (b *blockingRuntime) RunOnSession(ctx context.Context, _ *config.OliumConfig, _ AgentSession, _ string, _, _ io.Writer, _ bool) (oliumRunOutput, error) {
	<-ctx.Done()
	return oliumRunOutput{}, ctx.Err()
}

func preflightEngine(rt AgentRuntime, timeout string) *Engine {
	s := &config.Settings{}
	s.Agent.Olium.PreflightTimeout = timeout
	return &Engine{settings: s, runtime: rt}
}

// TestPreflightHonorsContext: a cancelled caller ctx stops the ping at once
// (Ctrl-C used to wait out a hard-coded 5s on context.Background()).
func TestPreflightHonorsContext(t *testing.T) {
	e := preflightEngine(&blockingRuntime{}, "1m")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	err := e.Preflight(ctx)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 2*time.Second, "a cancelled ctx must return immediately")
	var pe *PreflightError
	require.True(t, errors.As(err, &pe))
	assert.Equal(t, apicontract.CodePreflightFailed, pe.Code())
}

// TestPreflightTimeoutNamesTheFlag: the configured deadline bounds the ping
// and the message tells the operator which knob to turn.
func TestPreflightTimeoutNamesTheFlag(t *testing.T) {
	e := preflightEngine(&blockingRuntime{}, "50ms")
	err := e.Preflight(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--preflight-timeout")
	assert.Contains(t, err.Error(), "50ms")
	var pe *PreflightError
	require.True(t, errors.As(err, &pe))
	assert.Equal(t, apicontract.CodePreflightFailed, pe.Code())
}

// TestPreflightProviderMissing: a provider that cannot be built is
// provider_missing, with the shared setup hint (decision D25).
func TestPreflightProviderMissing(t *testing.T) {
	e := preflightEngine(&blockingRuntime{newErr: errors.New("OPENAI_API_KEY is not set")}, "")
	err := e.Preflight(context.Background())
	require.Error(t, err)
	var pe *PreflightError
	require.True(t, errors.As(err, &pe))
	assert.Equal(t, apicontract.CodeProviderMissing, pe.Code())
	assert.Contains(t, err.Error(), "auto-detected unless agent.olium.provider is set")
}

// TestPreflightOK: a provider that answers passes.
func TestPreflightOK(t *testing.T) {
	e := preflightEngine(&fakeRuntime{output: "OK"}, "")
	require.NoError(t, e.Preflight(context.Background()))
}

// TestEffectivePreflightTimeout: 15s by default, 60s for a loopback endpoint,
// the configured value when it parses.
func TestEffectivePreflightTimeout(t *testing.T) {
	c := config.OliumConfig{Provider: "openai-api-key"}
	assert.Equal(t, config.DefaultPreflightTimeout, c.EffectivePreflightTimeout())
	c = config.OliumConfig{Provider: "openai-compatible"}
	c.CustomProvider.BaseURL = "http://localhost:11434/v1"
	assert.Equal(t, config.DefaultLocalPreflightTimeout, c.EffectivePreflightTimeout())
	c.CustomProvider.BaseURL = "http://127.0.0.1:1234/v1"
	assert.Equal(t, config.DefaultLocalPreflightTimeout, c.EffectivePreflightTimeout())
	c.CustomProvider.BaseURL = "https://openrouter.ai/api/v1"
	assert.Equal(t, config.DefaultPreflightTimeout, c.EffectivePreflightTimeout())
	c.PreflightTimeout = "3s"
	assert.Equal(t, 3*time.Second, c.EffectivePreflightTimeout())
	c.PreflightTimeout = "garbage"
	assert.Equal(t, config.DefaultPreflightTimeout, c.EffectivePreflightTimeout())
}

// TestRunBudgetTripsOnce: the engine charges each call and cancels the run on
// the first cap crossed, exactly once.
func TestRunBudgetTripsOnce(t *testing.T) {
	e := &Engine{}
	var tripped []*BudgetExhaustedError
	e.SetRunBudget(RunBudget{MaxCommands: 3, TokenBudget: 1_000}, func(b *BudgetExhaustedError) { tripped = append(tripped, b) })

	e.chargeRunBudget(agenttypes.TokenUsage{InputTokens: 100, OutputTokens: 50}, 1)
	assert.Nil(t, e.BudgetExhausted())
	e.chargeRunBudget(agenttypes.TokenUsage{InputTokens: 100}, 2)
	require.NotNil(t, e.BudgetExhausted())
	assert.Equal(t, BudgetStopCommands, e.BudgetExhausted().Stop)
	e.chargeRunBudget(agenttypes.TokenUsage{InputTokens: 5_000}, 0)
	require.Len(t, tripped, 1, "the callback fires once")
	calls, _ := e.RunBudgetUsage()
	assert.Equal(t, 3, calls)

	e2 := &Engine{}
	e2.SetRunBudget(RunBudget{TokenBudget: 100}, nil)
	e2.chargeRunBudget(agenttypes.TokenUsage{InputTokens: 80, OutputTokens: 30}, 0)
	require.NotNil(t, e2.BudgetExhausted())
	assert.Equal(t, BudgetStopTokens, e2.BudgetExhausted().Stop)

	e3 := &Engine{}
	e3.SetRunBudget(RunBudget{MaxCostUSD: 0.000001, Model: "claude-sonnet-4"}, nil)
	e3.chargeRunBudget(agenttypes.TokenUsage{InputTokens: 10_000}, 0)
	require.NotNil(t, e3.BudgetExhausted())
	assert.Equal(t, BudgetStopCost, e3.BudgetExhausted().Stop)
}
