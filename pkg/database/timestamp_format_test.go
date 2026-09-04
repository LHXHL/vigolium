package database

import (
	"testing"
	"time"
)

// TestDBTimestampStringPreservesPostgresPrecision pins the reason
// dbTimestampString takes a driver at all.
//
// The keyset predicates in dbsource.go compare a value read back OUT of the
// database against the column it came from: `created_at < ? OR (created_at = ?
// AND uuid <= ?)`. PostgreSQL stores created_at as a real `timestamp` with
// microsecond precision and compares numerically, so rendering the bound at
// second precision puts it strictly BEFORE every row written in that same
// second — both halves of the predicate go false and the page comes back empty.
// The failure is silent: the dynamic-assessment phase reports "0 items" and the
// scan finishes clean against a database full of records.
//
// SQLite needs the opposite: created_at there is TEXT written by
// CURRENT_TIMESTAMP at second precision and compared lexically, so a fractional
// part would sort after every stored value and match nothing.
func TestDBTimestampStringPreservesPostgresPrecision(t *testing.T) {
	// A timestamp as PostgreSQL hands it back — microseconds, not a whole second.
	ts := time.Date(2026, 9, 3, 23, 37, 24, 595527000, time.UTC)

	if got, want := dbTimestampString(driverPostgres, ts), "2026-09-03 23:37:24.595527"; got != want {
		t.Errorf("postgres: dbTimestampString = %q, want %q (truncating here matches zero rows)", got, want)
	}
	if got, want := dbTimestampString(driverSQLite, ts), "2026-09-03 23:37:24"; got != want {
		t.Errorf("sqlite: dbTimestampString = %q, want %q (a fractional part sorts past every stored value)", got, want)
	}

	// A whole second must still render its zero microseconds on PostgreSQL, so the
	// format is fixed-width and a stored .000000 compares equal either way.
	whole := time.Date(2026, 9, 3, 23, 37, 24, 0, time.UTC)
	if got, want := dbTimestampString(driverPostgres, whole), "2026-09-03 23:37:24.000000"; got != want {
		t.Errorf("postgres whole second: dbTimestampString = %q, want %q", got, want)
	}

	// An unknown driver falls back to the SQLite rendering rather than the
	// wider one: a text column is the format that cannot absorb the other's.
	if got, want := dbTimestampString("", ts), "2026-09-03 23:37:24"; got != want {
		t.Errorf("unknown driver: dbTimestampString = %q, want %q", got, want)
	}

	// Local-zone input is normalized to UTC, matching how the columns are stored.
	loc := time.FixedZone("UTC+7", 7*60*60)
	if got, want := dbTimestampString(driverPostgres, ts.In(loc)), "2026-09-03 23:37:24.595527"; got != want {
		t.Errorf("non-UTC input: dbTimestampString = %q, want %q", got, want)
	}
}
