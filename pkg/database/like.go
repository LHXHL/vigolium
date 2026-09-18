package database

import "strings"

// SQL LIKE pattern construction for user-supplied text.
//
// Every substring filter in the read surface (--search, --header, --body, the
// positional fuzzy term, --exclude-*, --host, --path, …) ends up as a LIKE
// pattern. Building that pattern by concatenating "%" + term + "%" hands the
// user's own text to the pattern language: `%` becomes "any run of characters"
// and `_` becomes "any single character".
//
// That is not a theoretical leak. On a seeded store, `--body '%'` matched all 60
// records instead of the ones containing a percent sign, and `--body 'a_c'`
// matched 35 — every row with "abc", "a-c", "a/c" and so on. The terms this
// scanner is driven with are exactly the ones that trip it: URL-encoded payloads
// (%27, %00, %2e%2e), and snake_case identifiers (api_key, access_token,
// client_secret) which silently also match api-key, apiXkey and accessXtoken.
// The result is a wrong answer with no signal that anything was interpreted.
//
// So terms are escaped, and the predicates carry an explicit ESCAPE clause.
// SQLite has NO default LIKE escape character, so the clause is load-bearing
// there rather than decorative; Postgres defaults to backslash already and is
// unchanged by naming it.

// likeEscapeChar is the escape character named in every ESCAPE clause. It is a
// single backslash in SQL. Both drivers see it as one character: Postgres has
// standard_conforming_strings on by default, so '\' is a literal backslash and
// not the start of a C-style escape.
const likeEscapeChar = `\`

// likeEscapeClause is appended after each LIKE placeholder. Keep the leading
// space: it is concatenated directly onto "LIKE ?".
const likeEscapeClause = ` ESCAPE '\'`

// EscapeLikeLiteral neutralizes the LIKE metacharacters in s so the string
// matches itself. The escape character is escaped first; doing it last would
// double the backslashes this function just introduced.
func EscapeLikeLiteral(s string) string {
	s = strings.ReplaceAll(s, likeEscapeChar, likeEscapeChar+likeEscapeChar)
	s = strings.ReplaceAll(s, "%", likeEscapeChar+"%")
	s = strings.ReplaceAll(s, "_", likeEscapeChar+"_")
	return s
}

// LikeContains renders term as a pattern matching any row that CONTAINS it as a
// literal substring. This is the shape almost every search filter wants.
func LikeContains(term string) string {
	return "%" + EscapeLikeLiteral(term) + "%"
}

// LikeGlob renders a user-facing glob as a LIKE pattern, where `*` is the only
// wildcard. It backs the filters documented as accepting wildcards (--host,
// --path): `*` becomes `%`, and every other metacharacter — including a `%` or
// `_` the user typed — stays literal.
//
// The caller decides whether a pattern without a `*` means "contains" or
// "equals"; this function only translates.
func LikeGlob(pattern string) string {
	return strings.ReplaceAll(EscapeLikeLiteral(pattern), "*", "%")
}

// WithLikeEscape appends the ESCAPE clause to every `LIKE ?` placeholder in a
// predicate.
//
// It is a rewrite rather than 30 hand-edited SQL strings on purpose. The
// predicates in this package span multi-line raw strings with up to twelve
// placeholders each, and an ESCAPE clause missed on one branch is a filter that
// silently keeps the old over-matching behavior — the exact failure mode this
// whole file exists to remove. Rewriting makes the guarantee positional: if the
// text says LIKE ?, it carries an ESCAPE.
//
// Call it once per predicate at package level where possible; the per-query cost
// is a single pass over a short constant string.
func WithLikeEscape(pred string) string {
	return strings.ReplaceAll(pred, "LIKE ?", "LIKE ?"+likeEscapeClause)
}
