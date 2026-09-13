package cli

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"testing"
)

// gzipOf compresses body, so a fixture can exceed the decoder cap without a
// multi-megabyte literal in the repo.
func gzipOf(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(body); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// A gzip body larger than agentGunzipCap must report the size and digest of the
// WHOLE body and flag itself as capped — under --full-body too.
//
// The regression this locks: the decoder could not distinguish "stream ended at
// the cap" from "stream was cut at the cap", so an oversized response came back
// as 1 MiB with body_size=1048576, no body_truncated, and no body_sha256. An
// agent searching that body for evidence found nothing and concluded there was
// nothing to find.
func TestBodyViewReportsGzipDecoderCap(t *testing.T) {
	full := bytes.Repeat([]byte("A"), agentGunzipCap+5000)
	full = append(full, []byte("CANARY")...)
	wantSum := sha256.Sum256(full)
	wantHex := hex.EncodeToString(wantSum[:])

	raw := append([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"), gzipOf(t, full)...)

	for _, tc := range []struct {
		name string
		opts agentViewOptions
	}{
		{"bounded preview", agentViewOptions{}},
		{"full body", agentViewOptions{fullBody: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := bodyView(raw, "text/plain", agentRespBodyPreviewMax, tc.opts)

			if got := v["body_size"]; got != len(full) {
				t.Errorf("body_size = %v, want the TRUE decoded size %d", got, len(full))
			}
			if v["body_truncated"] != true {
				t.Errorf("body_truncated = %v, want true — the body is a prefix", v["body_truncated"])
			}
			if got := v["body_sha256"]; got != wantHex {
				t.Errorf("body_sha256 = %v, want digest of the COMPLETE body %s", got, wantHex)
			}
			if v["decoder_capped"] != true {
				t.Errorf("decoder_capped = %v, want true", v["decoder_capped"])
			}
		})
	}
}

// The measuring pass must be bounded. DEFLATE reaches ~1032:1, so draining "the
// rest of the stream" is attacker-controlled work on bodies that come from the
// scanned target: a ~0.5 MB stored body expands to ~512 MB. Past agentMeasureCap
// the size is reported as a FLOOR and no digest is claimed, rather than the
// process spending unbounded CPU to refine a number.
func TestGunzipBoundedMeasurePassIsBounded(t *testing.T) {
	// Compresses to a few hundred KB; expands well past agentMeasureCap.
	huge := bytes.Repeat([]byte("A"), agentMeasureCap+(8<<20))
	dec := gunzipBounded(gzipOf(t, huge), true)

	if !dec.Capped {
		t.Fatal("Capped = false, want true for a body past the decoder cap")
	}
	if !dec.SizeIsFloor {
		t.Error("SizeIsFloor = false: a measurement that hit its own bound must be reported as a lower bound")
	}
	if dec.FullSHA256 != "" {
		t.Error("FullSHA256 set despite an unfinished measuring pass — a digest over a prefix is worse than none")
	}
	if len(dec.Bytes) != agentGunzipCap {
		t.Errorf("retained %d bytes, want exactly the %d-byte cap", len(dec.Bytes), agentGunzipCap)
	}
	// The floor is still a true lower bound.
	if dec.FullSize <= agentGunzipCap {
		t.Errorf("FullSize = %d, want a floor above the decoder cap", dec.FullSize)
	}

	// bodyView must name it as a floor, never as body_size.
	raw := append([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"), gzipOf(t, huge)...)
	v := bodyView(raw, "text/plain", agentRespBodyPreviewMax, agentViewOptions{})
	if _, ok := v["body_size"]; ok {
		t.Error("body_size emitted for an unfinished measurement; want body_size_at_least")
	}
	if _, ok := v["body_size_at_least"]; !ok {
		t.Error("body_size_at_least missing")
	}
	if _, ok := v["body_sha256"]; ok {
		t.Error("body_sha256 emitted without a complete measurement")
	}
}

// Text-only callers must not pay for the measuring pass they discard.
func TestMaybeGunzipSkipsMeasurement(t *testing.T) {
	full := bytes.Repeat([]byte("B"), agentGunzipCap+5000)
	gz := gzipOf(t, full)

	if got := len(maybeGunzip(gz)); got != agentGunzipCap {
		t.Errorf("maybeGunzip returned %d bytes, want the %d-byte cap", got, agentGunzipCap)
	}
	unmeasured := gunzipBounded(gz, false)
	if !unmeasured.Capped {
		t.Error("Capped must still be reported without measuring — it costs one byte")
	}
	if unmeasured.FullSHA256 != "" {
		t.Error("FullSHA256 computed for a non-measuring caller that discards it")
	}
	if measured := gunzipBounded(gz, true); measured.FullSize != len(full) {
		t.Errorf("measuring pass FullSize = %d, want %d", measured.FullSize, len(full))
	}
}

// A gzip body that fits under the cap must NOT be flagged as capped, and keeps
// the cheap path (no digest for a fully inlined body).
func TestBodyViewSmallGzipNotFlaggedCapped(t *testing.T) {
	full := []byte("a small decodable body")
	raw := append([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"), gzipOf(t, full)...)

	v := bodyView(raw, "text/plain", agentRespBodyPreviewMax, agentViewOptions{})
	if v["body_size"] != len(full) {
		t.Errorf("body_size = %v, want %d", v["body_size"], len(full))
	}
	if _, ok := v["decoder_capped"]; ok {
		t.Error("decoder_capped set for a body that fit under the cap")
	}
	if v["body_truncated"] != nil {
		t.Errorf("body_truncated = %v, want unset", v["body_truncated"])
	}
	if v["body"] != string(full) {
		t.Errorf("body = %q, want the decoded text", v["body"])
	}
}

// An unknown --fields name must be rejected, naming the supported set. Silently
// dropping it made "unsupported field", "typo" and "null value" one outcome.
func TestValidateFieldSelectionRejectsUnknown(t *testing.T) {
	err := validateFieldSelection([]string{"uuid", "response_body_sha256"}, trafficViewFields)
	if err == nil {
		t.Fatal("expected an error for an unsupported field name")
	}
	if !strings.Contains(err.Error(), "response_body_sha256") {
		t.Errorf("error must name the offending field, got: %v", err)
	}
	if !strings.Contains(err.Error(), "supported fields") {
		t.Errorf("error must list the supported set, got: %v", err)
	}
	if classifyExitCode(err) != ExitUsageError {
		t.Errorf("a bad field name must exit %d (usage), got %d", ExitUsageError, classifyExitCode(err))
	}
	if err := validateFieldSelection([]string{"uuid", "status_code"}, trafficViewFields); err != nil {
		t.Errorf("supported fields rejected: %v", err)
	}
}

// --fields must not be able to delete a key the caller requested through a
// different flag. `--with-records --fields id` used to return the finding with
// no evidence at all, exit 0.
func TestProjectFieldsKeepsAlwaysKeys(t *testing.T) {
	m := map[string]any{"id": 1, "severity": "high", "records": []any{"r1"}}
	got := projectFields(m, []string{"id"}, "records")

	if _, ok := got["records"]; !ok {
		t.Error("records was dropped by a --fields projection that did not name it")
	}
	if _, ok := got["severity"]; ok {
		t.Error("severity survived a projection that did not name it")
	}
	// Without the always-set, the projection still narrows as documented.
	if _, ok := projectFields(m, []string{"id"})["records"]; ok {
		t.Error("projectFields with no always-keys should narrow to exactly the named keys")
	}
}

// The traffic/finding field vocabularies are the contract --fields validates
// against, so a key the view emits must be selectable. This catches a field
// added to a view but not to its descriptor, which would make a real field
// look unsupported.
func TestViewFieldVocabulariesCoverEmittedKeys(t *testing.T) {
	for _, name := range []string{"uuid", "url", "host", "status_code", "request", "response"} {
		if !slices.Contains(trafficViewFields, name) {
			t.Errorf("trafficViewFields missing emitted key %q", name)
		}
	}
	for _, name := range []string{"id", "severity", "url", "matched_at", "records"} {
		if !slices.Contains(findingViewFields, name) {
			t.Errorf("findingViewFields missing emitted key %q", name)
		}
	}
}
