package discovery

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEngineMetrics_SurfaceCoordinatorScheduling: the coordinator's preemption
// and inline-worker counters reach the engine's metrics snapshot, so a caller
// can tell a busy expander from one parked behind urgent work.
func TestEngineMetrics_SurfaceCoordinatorScheduling(t *testing.T) {
	server := testServer()
	defer server.Close()

	engine, err := testEngineWithConfig(testConfig(server.URL))
	require.NoError(t, err)
	defer engine.Stop()

	m := engine.coordinator.Metrics()
	m.InlineInFlight.Store(2)
	m.ExpansionsInFlight.Store(3)
	m.SuspendedExpansions.Store(1)
	m.Preemptions.Store(7)

	got := engine.GetMetrics()
	assert.Equal(t, int32(2), got.InlineInFlight)
	assert.Equal(t, int32(3), got.ExpansionsInFlight)
	assert.Equal(t, int32(1), got.SuspendedExpansions)
	assert.Equal(t, uint64(7), got.Preemptions)

	// Reset so Stop's quiescence accounting is not confused by the fakes.
	m.InlineInFlight.Store(0)
	m.ExpansionsInFlight.Store(0)
	m.SuspendedExpansions.Store(0)
}
