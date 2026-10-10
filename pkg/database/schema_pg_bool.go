package database

import (
	"context"
	"fmt"
	"slices"

	"github.com/uptrace/bun"
	"go.uber.org/zap"
)

// Legacy Postgres bool columns.
//
// Before the schema DDL became per-dialect templates (schema_ddl.go), Postgres
// DDL was SQLite DDL rewritten by string matching, and a bool column the
// rewrite did not recognise was created as INTEGER. chain_truncated never was
// recognised, and a column added by a column migration (is_authenticated on an
// older store) never went through the rewrite at all. Postgres refuses to write
// a Go bool into an INTEGER column, so on such a store every write of those
// rows fails.
//
// CREATE TABLE IF NOT EXISTS and ADD COLUMN cannot fix an existing column, so
// CreateSchema converts any {{BOOL}} column a Postgres store still holds as an
// integer type, in place, and schemaGapsDetail reports one as a gap so the
// readiness check sends the store through CreateSchema.

// pgIntegerTypes are the information_schema data_type values a legacy bool
// column can have. Anything else that is not boolean is left alone and logged:
// converting an unknown type by guesswork could destroy data.
var pgIntegerTypes = map[string]bool{"smallint": true, "integer": true, "bigint": true}

// legacyBoolColumns returns the {{BOOL}} columns this Postgres store holds as a
// type other than boolean, with that type. Nil on SQLite, where a bool is an
// INTEGER by design.
func (db *DB) legacyBoolColumns(ctx context.Context) (map[boolColumn]string, error) {
	if db.driver != driverPostgres {
		return nil, nil
	}
	bools := schemaBoolColumns()
	var tables []string
	want := make(map[string]boolColumn, len(bools))
	for _, b := range bools {
		if !slices.Contains(tables, b.Table) {
			tables = append(tables, b.Table)
		}
		want[b.Table+"."+b.Column] = b
	}
	rows, err := db.QueryContext(ctx,
		`SELECT table_name, column_name, data_type FROM information_schema.columns
		 WHERE table_schema = 'public' AND data_type <> 'boolean' AND table_name IN (?)`,
		bun.List(tables))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[boolColumn]string{}
	for rows.Next() {
		var table, column, typ string
		if err := rows.Scan(&table, &column, &typ); err != nil {
			return nil, err
		}
		if b, ok := want[table+"."+column]; ok {
			out[b] = typ
		}
	}
	return out, rows.Err()
}

// convertLegacyBoolColumns rewrites every legacy integer bool column on a
// Postgres store to BOOLEAN (nonzero → TRUE), restoring its template default.
// Each column converts in its own transaction — Postgres DDL is transactional,
// so a failure leaves that column exactly as it was. A no-op on SQLite and on a
// store with nothing to convert, which costs one catalog query.
//
// Converting rewrites the table, so on a large http_records it runs once, for
// as long as a full-table rewrite takes, and never again.
func (db *DB) convertLegacyBoolColumns(ctx context.Context) error {
	legacy, err := db.legacyBoolColumns(ctx)
	if err != nil {
		return fmt.Errorf("read bool column types: %w", err)
	}
	for b, typ := range legacy {
		if !pgIntegerTypes[typ] {
			zap.L().Warn("bool column has an unexpected type; leaving it unconverted",
				zap.String("column", b.Table+"."+b.Column), zap.String("type", typ))
			continue
		}
		def := "FALSE"
		if b.Default {
			def = "TRUE"
		}
		zap.L().Info("converting legacy integer column to boolean",
			zap.String("column", b.Table+"."+b.Column), zap.String("from", typ))
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, stmt := range []string{
			fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s DROP DEFAULT", b.Table, b.Column),
			fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s TYPE BOOLEAN USING (%s <> 0)", b.Table, b.Column, b.Column),
			fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s SET DEFAULT %s", b.Table, b.Column, def),
		} {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("convert %s.%s to boolean: %w", b.Table, b.Column, err)
			}
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("convert %s.%s to boolean: %w", b.Table, b.Column, err)
		}
	}
	return nil
}
