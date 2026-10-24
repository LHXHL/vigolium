package database

import (
	"strings"

	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/schema"
)

// Since bun v1.3 a string containing a NUL byte fails the whole query
// ("bun: string contains a NUL byte") instead of having the NULs stripped.
// Scan data routinely carries them (raw requests, response excerpts, evidence
// such as /proc/self/environ), and neither SQLite text nor PostgreSQL text can
// hold one anyway, so these dialects keep the pre-1.3 behavior: strip, then quote.

type sqliteDialect struct{ *sqlitedialect.Dialect }

type pgDialect struct{ *pgdialect.Dialect }

// NewSQLiteDialect returns the SQLite dialect every store opener should use.
func NewSQLiteDialect() schema.Dialect { return sqliteDialect{sqlitedialect.New()} }

// NewPGDialect returns the PostgreSQL dialect every store opener should use.
func NewPGDialect() schema.Dialect { return pgDialect{pgdialect.New()} }

func (d sqliteDialect) AppendString(b []byte, s string) []byte {
	return d.Dialect.AppendString(b, stripNUL(s))
}

func (d pgDialect) AppendString(b []byte, s string) []byte {
	return d.Dialect.AppendString(b, stripNUL(s))
}

func stripNUL(s string) string {
	if strings.IndexByte(s, 0) < 0 {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "")
}
