package database

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/schema"
)

// A NUL byte in a string column must be stripped, not fail the whole query
// (bun v1.3 made the bare dialects reject it).
func TestDialectsStripNUL(t *testing.T) {
	for name, d := range map[string]schema.Dialect{"sqlite": NewSQLiteDialect(), "postgres": NewPGDialect()} {
		t.Run(name, func(t *testing.T) {
			q := bun.NewDB(nil, d).NewInsert().Model(&Finding{FindingHash: "h", Request: "GET /\x00 HTTP/1.1"}).String()
			assert.NotContains(t, q, "?!(")
			assert.Contains(t, q, "'GET / HTTP/1.1'")
		})
	}
}
