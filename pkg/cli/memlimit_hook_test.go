package cli

import (
	"math"
	"os"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// restoreMemHookState snapshots the process-global memory limit, GOMEMLIMIT env,
// and the package globals applyScanMemLimit reads, restoring them after the test.
func restoreMemHookState(t *testing.T) {
	t.Helper()
	origLimit := debug.SetMemoryLimit(-1)
	origEnv, hadEnv := os.LookupEnv("GOMEMLIMIT")
	origMemLimit, origParallel, origSilent := globalMemLimit, globalParallel, globalSilent
	origCeil := scanHeapCeiling
	t.Cleanup(func() {
		debug.SetMemoryLimit(origLimit)
		if hadEnv {
			_ = os.Setenv("GOMEMLIMIT", origEnv)
		} else {
			_ = os.Unsetenv("GOMEMLIMIT")
		}
		globalMemLimit, globalParallel, globalSilent = origMemLimit, origParallel, origSilent
		scanHeapCeiling = origCeil
	})
	globalSilent = true // keep the note off the test output
}

// applyScanMemLimit must set a ceiling for scan-driving commands and leave
// non-scan commands (and the process limit) untouched.
func TestApplyScanMemLimitGating(t *testing.T) {
	t.Run("scan command gets an explicit ceiling", func(t *testing.T) {
		restoreMemHookState(t)
		require.NoError(t, os.Unsetenv("GOMEMLIMIT"))
		globalMemLimit, globalParallel = "1GiB", 1

		applyScanMemLimit(cmdAtPath("scan"))
		assert.Equal(t, int64(1<<30), debug.SetMemoryLimit(-1))
		assert.Equal(t, "1073741824", os.Getenv("GOMEMLIMIT"), "must export for -P children")
	})

	t.Run("non-scan command is left alone", func(t *testing.T) {
		restoreMemHookState(t)
		require.NoError(t, os.Unsetenv("GOMEMLIMIT"))
		debug.SetMemoryLimit(math.MaxInt64) // known unlimited baseline
		globalMemLimit, globalParallel = "1GiB", 1

		applyScanMemLimit(cmdAtPath("extensions run"))
		assert.Equal(t, int64(math.MaxInt64), debug.SetMemoryLimit(-1), "extensions run must not get a ceiling")
		_, set := os.LookupEnv("GOMEMLIMIT")
		assert.False(t, set, "non-scan command must not export GOMEMLIMIT")
	})

	t.Run("auto mode sets some positive ceiling for a scan", func(t *testing.T) {
		restoreMemHookState(t)
		require.NoError(t, os.Unsetenv("GOMEMLIMIT"))
		globalMemLimit, globalParallel = "", 2

		applyScanMemLimit(cmdAtPath("scan"))
		got := debug.SetMemoryLimit(-1)
		// On any normally-provisioned host this caps below the unlimited sentinel.
		assert.Less(t, got, int64(math.MaxInt64), "auto mode should set a real ceiling")
		assert.Positive(t, got)
	})
}
