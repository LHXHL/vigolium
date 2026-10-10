package httpstack

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/types"
)

// Close returns the network reference New took: the shared dialer is torn
// down once the only stack holding it closes. Several call sites used to leak
// that reference.
func TestNewCloseBalancesNetwork(t *testing.T) {
	require.Nil(t, network.CurrentDialer(), "no other holder in this test binary")

	s, err := New(Config{Options: types.DefaultOptions(), MaxHosts: 10, RateLimit: 5, Budget: egress.NewBudget(3, 0)})
	require.NoError(t, err)
	require.NotNil(t, network.CurrentDialer())
	require.NotNil(t, s.Requester)
	assert.NotNil(t, s.Services.RateLimiter)
	assert.NotNil(t, s.Services.Egress)
	assert.NotNil(t, s.Services.DedupManager)

	s.Close()
	s.Close() // idempotent
	assert.Nil(t, network.CurrentDialer())

	var none *Stack
	none.Close() // nil-safe
}

func TestNewWithoutRateLimit(t *testing.T) {
	s, err := New(Config{Options: types.DefaultOptions()})
	require.NoError(t, err)
	defer s.Close()
	assert.Nil(t, s.Services.RateLimiter, "0 = no global cap")
}

func TestHostLimiterConfig(t *testing.T) {
	cfg := HostLimiterConfig(4, 100, false, true)
	assert.Equal(t, 4, cfg.MaxPerHost)
	assert.Equal(t, 100, cfg.MaxEntries)
	assert.False(t, cfg.WafAutoArm, "no WAF pacing unless asked")
	assert.False(t, cfg.DisablePreArm)

	cfg = HostLimiterConfig(0, 0, true, true)
	assert.True(t, cfg.WafAutoArm)
	assert.True(t, cfg.DisablePreArm, "--no-waf-pacing drops only the pre-arm")
}
