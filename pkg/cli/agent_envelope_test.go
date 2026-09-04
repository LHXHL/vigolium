package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func marshalEnvelope(t *testing.T, env *agentEnvelope) map[string]any {
	t.Helper()
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v (%s)", err, raw)
	}
	return got
}

func TestEnvelopeCarriesSchemaVersionAndItems(t *testing.T) {
	// The whole point: one parser for every -j command. `items` is canonical and
	// `schema_version` is the number a consumer gates on.
	got := marshalEnvelope(t, newAgentEnvelope("traffic", "records", []string{"a"}, 1, 0, 100))
	if got["schema_version"] != float64(AgentSchemaVersion) {
		t.Errorf("schema_version = %v", got["schema_version"])
	}
	if got["command"] != "traffic" {
		t.Errorf("command = %v", got["command"])
	}
	if _, ok := got["items"]; !ok {
		t.Error("items missing")
	}
}

func TestEnvelopeKeepsLegacyKeyAsAlias(t *testing.T) {
	// Existing parsers keep working for one minor version; the alias points at
	// the same slice, and is to be removed rather than added to.
	got := marshalEnvelope(t, newAgentEnvelope("traffic", "records", []string{"a"}, 1, 0, 100))
	items, _ := json.Marshal(got["items"])
	legacy, _ := json.Marshal(got["records"])
	if string(items) != string(legacy) {
		t.Errorf("legacy alias diverges: items=%s records=%s", items, legacy)
	}
}

func TestEnvelopeStructFieldsWinOverExtra(t *testing.T) {
	// An alias that shadowed `items` or `total` would reintroduce exactly the
	// ambiguity the envelope removes.
	env := newAgentEnvelope("finding", "findings", []string{"real"}, 7, 0, 10)
	env.With("total", 999).With("items", []string{"fake"})
	got := marshalEnvelope(t, env)
	if got["total"] != float64(7) {
		t.Errorf("total = %v, want 7 (struct field must win)", got["total"])
	}
	items, _ := json.Marshal(got["items"])
	if string(items) != `["real"]` {
		t.Errorf("items = %s, want the struct value", items)
	}
}

func TestEnvelopeZeroTotalIsPresent(t *testing.T) {
	// "0 results" and "the field is missing" are different facts; a consumer
	// distinguishing an empty match from a broken query needs the former.
	got := marshalEnvelope(t, newAgentEnvelope("finding", "findings", []string{}, 0, 0, 100))
	if _, ok := got["total"]; !ok {
		t.Error("total dropped when zero")
	}
}

func TestEnvelopeTimestampPrecision(t *testing.T) {
	got := marshalEnvelope(t, newAgentEnvelope("traffic", "records", nil, 0, 0, 0))
	ts, _ := got["generated_at"].(string)
	if ts == "" {
		t.Fatal("generated_at missing")
	}
	dot := strings.IndexByte(ts, '.')
	if dot < 0 || len(ts)-dot-2 != 3 {
		t.Errorf("generated_at = %q, want exactly 3 fractional digits", ts)
	}
	if got["generated_at_ms"] == nil {
		t.Error("generated_at_ms missing — the numeric sibling is always present")
	}
}

func TestAgentTimestampZeroTimeIsEmpty(t *testing.T) {
	// A zero time is "not set", not 1970; emitting the epoch would make a missing
	// value look like a real one from 56 years ago.
	if got := agentTimestamp(time.Time{}); got != "" {
		t.Errorf("agentTimestamp(zero) = %q, want empty", got)
	}
}

func TestEnvelopeEncodesRowsOnce(t *testing.T) {
	// The legacy alias must reuse the bytes `items` already encoded to. Holding a
	// second reference to the slice serialized every row twice, doubling the size
	// of every -j payload for a field that is deprecated on arrival.
	rows := []string{"aaaaaaaaaa", "bbbbbbbbbb"}
	raw, err := json.Marshal(newAgentEnvelope("traffic", "records", rows, 2, 0, 100))
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(raw, []byte("aaaaaaaaaa")); n != 2 {
		t.Errorf("row appears %d times, want 2 (items + one alias)", n)
	}
	// Both names must still resolve to the same content.
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	items, _ := json.Marshal(got["items"])
	legacy, _ := json.Marshal(got["records"])
	if string(items) != string(legacy) {
		t.Errorf("alias diverged: %s vs %s", items, legacy)
	}
}

func TestAgentTimestampMatchesEventStream(t *testing.T) {
	// The -j envelope and the --events stream must render the same instant
	// identically, or a consumer correlating the two has to parse both.
	when := time.Date(2026, 9, 4, 1, 2, 3, 456789000, time.UTC)
	if agentTimestamp(when) != "2026-09-04T01:02:03.456Z" {
		t.Errorf("agentTimestamp = %q", agentTimestamp(when))
	}
}

func TestEnvelopeQueryIsOmittedWhenEmpty(t *testing.T) {
	got := marshalEnvelope(t, newAgentEnvelope("traffic", "records", nil, 0, 0, 0))
	if _, ok := got["query"]; ok {
		t.Error("query present but empty — omitempty should drop it")
	}
	env := newAgentEnvelope("traffic", "records", nil, 0, 0, 0).WithQuery("vigolium replay -u x")
	if marshalEnvelope(t, env)["query"] != "vigolium replay -u x" {
		t.Error("query not carried")
	}
}

func TestEnvelopeDoesNotEscapeHTML(t *testing.T) {
	env := newAgentEnvelope("traffic", "records", []string{"https://x/?a=1&b=<2>"}, 1, 0, 1)
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	for _, escape := range []string{`&`, `<`, `>`} {
		if strings.Contains(string(raw), escape) {
			t.Errorf("escaped %s: %s", escape, raw)
		}
	}
}
