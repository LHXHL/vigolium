package cli

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestScanFinishTotals_ModuleErrors: scan.finished carries the per-module error
// totals the runner persisted on scans.module_errors.
func TestScanFinishTotals_ModuleErrors(t *testing.T) {
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = filepath.Join(t.TempDir(), "module-errors.sqlite")
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.EnsureSchemaReady(context.Background()))

	repo := database.NewRepository(db)
	require.NoError(t, repo.CreateScan(context.Background(), &database.Scan{
		UUID:         "scan-module-errors",
		Status:       "completed",
		StartedAt:    time.Now(),
		ModuleErrors: map[string]int64{"ext-csp": 41, "sqli-error-based": 2},
	}))

	ev := &scanevents.Event{Type: scanevents.TypeScanFinished, Status: scanevents.StatusCompleted}
	scanFinishTotals(db, ev, &types.Options{ScanUUID: "scan-module-errors"})
	require.Equal(t, map[string]int64{"ext-csp": 41, "sqli-error-based": 2}, ev.ModuleErrors)

	ev = &scanevents.Event{Type: scanevents.TypeScanFinished}
	applyScanCompletion(ev, &database.Scan{})
	require.Nil(t, ev.ModuleErrors)
}
