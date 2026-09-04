package cli

import (
	"bytes"
	"encoding/json"
	"sort"
	"time"

	"github.com/vigolium/vigolium/pkg/scanevents"
)

// AgentSchemaVersion is the contract version of every -j/--json envelope. A
// consumer gates on it; it is bumped on any breaking field change.
//
// Its absence was the real problem. A driver could not write one parser, because
// different commands (and different vigolium versions) named the same thing
// differently — the row array was `data` or `records` or `traffic` or `results`
// or `http_records` depending on where you asked, and drift was discovered as a
// parse failure in production rather than as a version check at startup. There
// is now one shape, one canonical name per field, and a number to check.
const AgentSchemaVersion = 1

// agentEnvelope is the single JSON shape every -j command emits.
//
// `items` is canonical. Each command ALSO writes its historical key pointing at
// the same slice (see legacyKey) so existing parsers keep working for one minor
// version; those aliases are to be removed, never added to.
type agentEnvelope struct {
	SchemaVersion int    `json:"schema_version"`
	Command       string `json:"command"`
	ProjectUUID   string `json:"project_uuid,omitempty"`
	// DBPath names the database this command actually opened. A consumer that
	// pins $VIGOLIUM_DB_PATH and passes --db can then ASSERT the store it read
	// rather than trusting that the pin survived a subprocess chain — the default
	// database is one shared file, so a silent fall-through to it reads every
	// target that ever landed there.
	DBPath string `json:"db_path,omitempty"`

	Total  int64 `json:"total"`
	Offset int   `json:"offset"`
	Limit  int   `json:"limit"`

	Items any `json:"items"`

	// Query is a ready-to-run follow-up command for the obvious next step. It is
	// the cheapest documentation in the surface: a paragraph of consumer guidance
	// that cannot go stale, because it is generated from the same values the
	// envelope reports.
	Query string `json:"query,omitempty"`

	// GeneratedAt is stamped in the wire timestamp format (RFC3339, exactly three
	// fractional digits) with an epoch-millisecond sibling. See
	// agentTimestamp for why the precision is fixed.
	GeneratedAt   string `json:"generated_at,omitempty"`
	GeneratedAtMS int64  `json:"generated_at_ms,omitempty"`

	// extra carries command-specific fields. Marshaled by MarshalJSON into the
	// same object.
	extra map[string]any
	// legacyKey is the pre-envelope name this command used for its row array. It
	// is rendered by ALIASING the already-encoded `items` bytes rather than by
	// holding a second reference to the slice — encoding the rows twice doubled
	// every -j payload, which on a `traffic -j -n 10000` is tens of MB and a
	// doubled token bill for a field that is deprecated on arrival.
	legacyKey string
}

// newAgentEnvelope builds the standard envelope. legacyKey is the pre-envelope
// name this command used for its row array ("records", "findings", "scans", …);
// pass "" for a command that had none.
func newAgentEnvelope(command, legacyKey string, items any, total int64, offset, limit int) *agentEnvelope {
	now := time.Now()
	env := &agentEnvelope{
		SchemaVersion: AgentSchemaVersion,
		Command:       command,
		Total:         total,
		Offset:        offset,
		Limit:         limit,
		Items:         items,
		// One clock read for both: they are two representations of the SAME
		// instant, and a schema whose selling point is that a consumer can compare
		// them must not ship a pair sampled a millisecond apart.
		GeneratedAt:   agentTimestamp(now),
		GeneratedAtMS: scanevents.EpochMillis(now),
		extra:         map[string]any{},
	}
	env.legacyKey = legacyKey
	return env
}

// With attaches a command-specific field to the envelope.
func (e *agentEnvelope) With(key string, value any) *agentEnvelope {
	if e.extra == nil {
		e.extra = map[string]any{}
	}
	e.extra[key] = value
	return e
}

// WithQuery attaches the follow-up command.
func (e *agentEnvelope) WithQuery(q string) *agentEnvelope {
	e.Query = q
	return e
}

// envelopeFields is the struct's own JSON key set. Extra keys colliding with one
// are dropped: `items` and `total` are the contract, and an alias shadowing one
// would reintroduce exactly the ambiguity the envelope removes.
var envelopeFields = map[string]bool{
	"schema_version": true, "command": true, "project_uuid": true, "db_path": true,
	"total": true, "offset": true, "limit": true, "items": true, "query": true,
	"generated_at": true, "generated_at_ms": true,
}

// MarshalJSON merges the struct fields with extra (and the legacy row alias)
// into one flat object. Written by hand because the alias key is dynamic — it
// differs per command — and Go's struct tags cannot express that.
//
// It appends to the encoded struct rather than round-tripping through a
// map[string]any. That round trip decoded the whole result set — request and
// response bodies included — into a generic tree costing several times the
// JSON's size in live heap, purely to answer a key-collision question the fixed
// field set above already answers.
func (e *agentEnvelope) MarshalJSON() ([]byte, error) {
	type alias agentEnvelope
	base, err := jsonMarshalNoEscape((*alias)(e))
	if err != nil {
		return nil, err
	}
	if len(e.extra) == 0 && e.legacyKey == "" {
		return base, nil
	}

	out := bytes.TrimSuffix(bytes.TrimSpace(base), []byte("}"))
	appendField := func(key string, raw []byte) {
		if envelopeFields[key] {
			return
		}
		out = append(out, ',')
		keyJSON, _ := json.Marshal(key)
		out = append(out, keyJSON...)
		out = append(out, ':')
		out = append(out, raw...)
	}

	// The legacy alias reuses the bytes `items` already encoded to, so the rows
	// are serialized once no matter how many names point at them.
	if e.legacyKey != "" {
		itemsJSON, err := jsonMarshalNoEscape(e.Items)
		if err != nil {
			return nil, err
		}
		appendField(e.legacyKey, itemsJSON)
	}
	for _, key := range sortedExtraKeys(e.extra) {
		raw, err := jsonMarshalNoEscape(e.extra[key])
		if err != nil {
			return nil, err
		}
		appendField(key, raw)
	}
	return append(out, '}'), nil
}

// sortedExtraKeys keeps the appended fields in a stable order — map iteration is
// random, and a payload whose key order changes run to run defeats diffing.
func sortedExtraKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// agentTimestamp renders t for JSON output: RFC3339 UTC with exactly three
// fractional digits.
//
// Go's default renders a variable number of fractional digits, so vigolium
// emitted microseconds (…785113Z) while a consumer comparing against a
// JavaScript toISOString() has milliseconds (…785Z) — and lexically "…785113Z"
// sorts BEFORE "…785Z". The extra precision is not extra information to such a
// consumer, it is a broken comparison that silently drops same-instant rows. The
// epoch-millisecond sibling exists for consumers that would rather compare
// integers than strings; either is correct, and both are always present.
func agentTimestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return scanevents.FormatTime(t)
}

// jsonMarshalNoEscape keeps HTML escaping off throughout the envelope's own
// marshaling. Payload evidence is full of &, < and >; the
// standard encoder would turn each into a \u00XX escape, which costs tokens and
// makes a hand-read line harder to compare against what the scanner sent.
func jsonMarshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encode appends a newline; the caller is assembling a value, not a stream.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
