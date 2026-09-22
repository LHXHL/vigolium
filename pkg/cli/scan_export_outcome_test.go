package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/types"
)

// A requested artifact that was not written must reach the caller. Every one of
// these used to be a line on stderr and nothing else: the command exited 0, the
// --events stream said scan.finished status=completed, and the file was absent —
// three success signals for a run that produced no output.

func TestFinishStatelessExportReportsAnUnwritableDestination(t *testing.T) {
	db := newExportTestDB(t)
	seedFindingAndRecord(t, db, "proj", "a")

	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions, so the export would succeed")
	}
	dir := filepath.Join(t.TempDir(), "readonly")
	require.NoError(t, os.Mkdir(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	out := filepath.Join(dir, "result.jsonl")
	opts := &types.Options{Stateless: true, OutputFormats: []string{"jsonl"}, Output: out}

	err := finishStatelessExport(db, opts, out, false)
	require.Error(t, err, "an export that wrote nothing reported success")
	assert.Contains(t, err.Error(), out)
	_, statErr := os.Stat(out)
	assert.True(t, os.IsNotExist(statErr), "no artifact should exist at %s", out)
}

// One bad format must not cost the operator the formats that CAN be written: a
// caller who asked for jsonl AND sqlite is better served by the one that landed
// than by neither. The run still fails — it just fails with the other file on
// disk.
func TestFinishStatelessExportWritesWhatItCanAndStillFails(t *testing.T) {
	db := newExportTestDB(t)
	seedFindingAndRecord(t, db, "proj", "a")

	base := filepath.Join(t.TempDir(), "result")
	// A non-empty directory sitting on the sqlite artifact's path makes that one
	// format fail at the final rename — staging succeeds, since it lands under its
	// own name in the same parent — while jsonl beside it succeeds.
	require.NoError(t, os.Mkdir(base+".sqlite", 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(base+".sqlite", "occupied"), []byte("x"), 0o600))

	opts := &types.Options{Stateless: true, OutputFormats: []string{"jsonl", "sqlite"}, Output: base}

	err := finishStatelessExport(db, opts, base, false)
	require.Error(t, err, "the sqlite format could not be written and the export reported success")
	assert.Contains(t, err.Error(), "sqlite")

	info, statErr := os.Stat(base + ".jsonl")
	require.NoError(t, statErr, "the format that could be written was skipped after the other one failed")
	assert.Positive(t, info.Size())
}

// The destructive failure: exportStatelessSQLite used to os.Remove the
// destination before VACUUM INTO, so a copy that could not finish left the
// operator with neither the new export nor the artifact it replaced.
func TestExportStatelessSQLiteKeepsThePreviousArtifactOnFailure(t *testing.T) {
	db := newExportTestDB(t)
	seedFindingAndRecord(t, db, "proj", "a")

	out := filepath.Join(t.TempDir(), "prior.sqlite")
	const priorContent = "the previous good export"
	require.NoError(t, os.WriteFile(out, []byte(priorContent), 0o600))

	// A cancelled context fails the VACUUM after staging has already begun —
	// standing in for the full disk, the Ctrl-C, and the killed process that all
	// reach the same point.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := exportStatelessSQLite(ctx, db, out)
	require.Error(t, err)

	got, readErr := os.ReadFile(out)
	require.NoError(t, readErr, "the previous artifact was deleted by a failed export")
	assert.Equal(t, priorContent, string(got), "the previous artifact was overwritten by a failed export")

	// The artifact is also the ONLY thing left: a staging file abandoned in the
	// operator's output directory looks like a result.
	entries, listErr := os.ReadDir(filepath.Dir(out))
	require.NoError(t, listErr)
	require.Len(t, entries, 1, "a failed export left litter beside the artifact")
	assert.Equal(t, filepath.Base(out), entries[0].Name())
}

func TestExportStatelessSQLiteReplacesAnExistingArtifact(t *testing.T) {
	db := newExportTestDB(t)
	seedFindingAndRecord(t, db, "proj", "a")

	out := filepath.Join(t.TempDir(), "result.sqlite")
	require.NoError(t, os.WriteFile(out, []byte("stale"), 0o600))
	// A stale sidecar describes the file being replaced, not the new one; left in
	// place SQLite would rather trust it than the fresh database beside it.
	require.NoError(t, os.WriteFile(out+"-wal", []byte("stale wal"), 0o600))

	got, err := exportStatelessSQLite(context.Background(), db, out)
	require.NoError(t, err)
	assert.Equal(t, out, got.path)

	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)
	assert.True(t, strings.HasPrefix(string(data), "SQLite format 3"),
		"the export did not replace the stale file with a real database")

	_, walErr := os.Stat(out + "-wal")
	assert.True(t, os.IsNotExist(walErr), "a stale -wal survived the export")
}

// recordExportFailure's precedence is a contract, not an implementation detail:
// it decides what a CI job and an agent see.
func TestRecordExportFailurePrecedence(t *testing.T) {
	exportErr := errors.New("export jsonl /tmp/out.jsonl: permission denied")

	t.Run("no error yet: the export failure becomes the result", func(t *testing.T) {
		var err error
		recordExportFailure(&err, exportErr)
		require.Error(t, err)
		assert.Equal(t, ExitError, classifyExitCode(err))
		assert.Equal(t, errCodeExportFailed, classifyErrorCode(err, ExitError))
	})

	t.Run("nothing failed: the result stays clean", func(t *testing.T) {
		var err error
		recordExportFailure(&err, nil)
		assert.NoError(t, err)
	})

	t.Run("a hard scan error wins: it is the cause", func(t *testing.T) {
		scanErr := fmt.Errorf("runner: target unreachable")
		err := scanErr
		recordExportFailure(&err, exportErr)
		assert.Equal(t, scanErr, err,
			"the export failed because the scan did; reporting the export hides the cause")
	})

	// The --fail-on gate is a COMPLETED result whose premise is that the output was
	// written before the code was chosen; when it wasn't, exit 4 would send a CI job
	// to read a file that does not exist. The gate is layered on by the CALLER
	// (withFailOnGate in runScanCmd), outside the defers that run
	// recordExportFailure — so what makes the export failure win is withFailOnGate
	// yielding to it as `prior`, not a branch inside recordExportFailure. Pin the
	// mechanism that actually runs.
	t.Run("the fail-on gate yields to a recorded export failure", func(t *testing.T) {
		var err error
		recordExportFailure(&err, exportErr)
		gated := withFailOnGate(err)
		assert.Equal(t, ExitError, classifyExitCode(gated),
			"a gate verdict whose artifact is missing must not report exit 4")
		assert.Equal(t, errCodeExportFailed, classifyErrorCode(gated, ExitError))
	})
}
