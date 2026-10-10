package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// The server keeps two pools on one store: the writer (ingest, scans, status
// updates) and, where the driver allows a separate one, a read-intent pool for
// the list/get handlers (database.DB.OpenReader). Browsing the UI then never
// borrows a writer connection, and a list request can never take the write
// lock — on SQLite the reader is query_only and opened without journal-mode or
// checkpoint side effects.

// openReadPool opens the read pool for db, or returns nil when db already
// serves reads as well as any second pool would (in-memory SQLite, a handle
// that is itself read-only). A failure degrades to the writer pool with a
// warning: reads still work, they just share connections with writes.
func openReadPool(db *database.DB) *database.DB {
	if db == nil {
		return nil
	}
	r, separate, err := db.OpenReader()
	if err != nil {
		zap.L().Warn("read pool unavailable; list endpoints will share the writer pool", zap.Error(err))
		return nil
	}
	if !separate {
		return nil
	}
	return r
}

// readerDB is the pool list/get handlers query: the read pool when there is
// one, the shared handle otherwise.
func (h *Handlers) readerDB() *database.DB {
	if h.readDB != nil {
		return h.readDB
	}
	return h.db
}

// readerRepo is readerDB as a repository.
func (h *Handlers) readerRepo() *database.Repository {
	if h.readRepo != nil {
		return h.readRepo
	}
	return h.repo
}

// listRetryPolicy bounds how long a list request rides out a busy store before
// answering database_locked. Shorter than the CLI's default: an HTTP client is
// waiting, and it can retry on its own schedule (Retry-After).
var listRetryPolicy = database.RetryPolicy{
	Op:          "list query",
	MaxAttempts: 6,
}

// retryRead runs a list/get query under the busy-retry budget.
func retryRead(ctx context.Context, fn func() error) error {
	return database.RetryBusy(ctx, fn, listRetryPolicy)
}

// respondQueryError renders a failed list/get query. An exhausted busy retry is
// 503 with Retry-After and the database_locked code (another writer holds the
// store; the request is worth repeating); anything else stays a 500.
func respondQueryError(c fiber.Ctx, err error) error {
	if errors.Is(err, database.ErrDatabaseLocked) {
		c.Set(fiber.HeaderRetryAfter, "2")
		// error_code is database_locked (errorCodeFor); details keeps carrying
		// it for clients written before error_code existed.
		return respondError(c, fiber.StatusServiceUnavailable, fmt.Errorf("query failed: %w", err), string(apicontract.CodeDatabaseLocked))
	}
	return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("query failed: %w", err))
}
