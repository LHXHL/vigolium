package database

// Chunking policy for the id/uuid IN() lists this package builds.
//
// The reason is NOT the bound-parameter ceiling, and assuming it was is how the
// wrong chunk size got picked before. Two facts, both measured against the
// dependencies in go.mod rather than inferred:
//
//   - Through database/sql and the modernc driver directly, a statement binds at
//     most 32766 parameters; 32767 fails with "too many SQL variables". That is
//     the ceiling maxSQLParams records, and it applies to the raw-SQL paths
//     (merge's pinned connection, the scratch-database probes).
//   - Through bun — which is every query builder call in this package — `?` and
//     bun.List do not produce bound parameters at all. The formatter interpolates
//     the values as SQL literals, so a 100k-element IN() list executes happily.
//
// So an unchunked list does not fail: it silently becomes a multi-megabyte SQL
// string, built and escaped element by element in Go and then parsed by SQLite,
// for a statement whose result is the same either way. Chunking bounds that
// string. It also bounds the raw-SQL paths below the hard ceiling, so a caller
// does not have to know which kind of path it is on.
//
// If a future bun upgrade switches to real parameter binding, the ceiling starts
// applying to these calls too — TestBunInterpolatesRatherThanBinds is the test
// that notices.
const (
	// maxSQLParams is the hard ceiling for paths that really do bind: the largest
	// number of bound parameters one statement can carry.
	maxSQLParams = 32766

	// SQLChunkSize is how many ids or uuids to put in one IN() list. It keeps the
	// generated SQL to a few hundred KB while staying under maxSQLParams with
	// room for the handful of other values a query carries (project scoping, a
	// date range, a LIMIT) — so one constant is correct on both kinds of path.
	SQLChunkSize = 8000
)
