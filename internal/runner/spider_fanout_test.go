package runner

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/pkg/types"
)

// fromFile is the shape every "the hint fires" case needs: -P only ever splits a
// -T file, so a suggestion is only honest for a file-driven run.
func fromFile(opts *types.Options) *types.Options {
	opts.SpideringEnabled = true
	opts.TargetsFilePaths = []string{"hosts.txt"}
	return opts
}

// TestSpiderFanOutSuggestion covers when the fan-out hint fires and, more
// importantly, which flags it names. Every condition mirrors one validateParallelScan
// enforces, so a suggestion that ignores the mode hands the operator a command that
// is rejected or silently degraded back to a single serial scan.
func TestSpiderFanOutSuggestion(t *testing.T) {
	tests := []struct {
		name        string
		opts        *types.Options
		targetCount int
		wantOK      bool
		wantFlags   string
	}{
		{
			name:        "persisted db suggests db-isolate",
			opts:        fromFile(&types.Options{}),
			targetCount: 682,
			wantOK:      true,
			wantFlags:   "--db-isolate -P 5",
		},
		{
			name:        "stateless suggests split-by-host, never db-isolate",
			opts:        fromFile(&types.Options{Stateless: true}),
			targetCount: 682,
			wantOK:      true,
			wantFlags:   "--split-by-host -P 5",
		},
		{
			name:        "stateless with split-by-host only needs -P",
			opts:        fromFile(&types.Options{Stateless: true, SplitByHost: true}),
			targetCount: 682,
			wantOK:      true,
			wantFlags:   "-P 5",
		},
		{
			name:        "db-isolate already set only needs -P",
			opts:        fromFile(&types.Options{DBIsolate: true}),
			targetCount: 682,
			wantOK:      true,
			wantFlags:   "-P 5",
		},
		{
			name:        "parallelism is capped at the target count",
			opts:        fromFile(&types.Options{}),
			targetCount: 2,
			wantOK:      true,
			wantFlags:   "--db-isolate -P 2",
		},
		{
			// The phase-level caller runs after seedTargetsFromTargetFiles has
			// promoted and cleared TargetsFilePaths; the run is still file-driven.
			name:        "seeded-from-file survives the cleared paths",
			opts:        &types.Options{SpideringEnabled: true, TargetsSeededFromFile: true},
			targetCount: 682,
			wantOK:      true,
			wantFlags:   "--db-isolate -P 5",
		},
		{
			// validateParallelScan warns and forces Parallel = 1 without a -T file,
			// so suggesting -P here yields a command that serializes anyway.
			name:        "no target file — -P would degrade back to a serial scan",
			opts:        &types.Options{SpideringEnabled: true},
			targetCount: 682,
			wantOK:      false,
		},
		{
			name:        "single target has nothing to fan out",
			opts:        fromFile(&types.Options{}),
			targetCount: 1,
			wantOK:      false,
		},
		{
			name:        "zero targets",
			opts:        fromFile(&types.Options{}),
			targetCount: 0,
			wantOK:      false,
		},
		{
			name:        "already fanning out needs no advice",
			opts:        fromFile(&types.Options{DBIsolate: true, Parallel: 5}),
			targetCount: 682,
			wantOK:      false,
		},
		{
			name:        "spidering disabled — the advice does not apply to other phases",
			opts:        &types.Options{TargetsFilePaths: []string{"hosts.txt"}},
			targetCount: 682,
			wantOK:      false,
		},
		{
			name:        "nil options",
			opts:        nil,
			targetCount: 682,
			wantOK:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags, ok := SpiderFanOutSuggestion(tt.opts, tt.targetCount)
			assert.Equal(t, tt.wantOK, ok)
			if !tt.wantOK {
				assert.Empty(t, flags)
				return
			}
			assert.Equal(t, tt.wantFlags, flags)
		})
	}
}

// TestSpiderFanOutSuggestionNeverPairsStatelessWithDBIsolate guards the one
// combination that is a hard error (`--db-isolate and --stateless are mutually
// exclusive`): a hint that produces a rejected command is worse than no hint.
func TestSpiderFanOutSuggestionNeverPairsStatelessWithDBIsolate(t *testing.T) {
	for _, split := range []bool{false, true} {
		flags, ok := SpiderFanOutSuggestion(fromFile(&types.Options{Stateless: true, SplitByHost: split}), 100)
		assert.True(t, ok)
		assert.NotContains(t, flags, "--db-isolate")
	}
}

// TestSpiderFanOutReasonMatchesTheTargetCount keeps the hint honest in both
// directions. Past the budget cap the run really does drop targets, so it says
// so; at or below the cap nothing is dropped and claiming otherwise would be a
// false alarm on the most common small run.
func TestSpiderFanOutReasonMatchesTheTargetCount(t *testing.T) {
	over := SpiderFanOutReason(spideringPhaseBudgetCap + 1)
	assert.Contains(t, over, "won't be reached")
	assert.Contains(t, over, "one host at a time")
	// Quotes the constant the ceiling is computed from: a hardcoded figure would
	// keep printing the old budget after the cap moved, and the operator sizes
	// their fan-out against it.
	assert.Contains(t, over, strconv.Itoa(spideringPhaseBudgetCap))

	at := SpiderFanOutReason(spideringPhaseBudgetCap)
	assert.NotContains(t, at, "won't be reached")
	assert.Contains(t, at, "one host at a time")

	under := SpiderFanOutReason(2)
	assert.NotContains(t, under, "won't be reached")
	assert.Contains(t, under, "2 targets")
}
