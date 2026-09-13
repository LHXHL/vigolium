package database

import (
	"encoding/json"

	"github.com/vigolium/vigolium/pkg/tlsprobe"
)

// HostFacts are the per-host observations a run collects alongside its records:
// the full DNS answer and, under --tls-probe, the TLS handshake and leaf
// certificate.
//
// They are NOT columns, and not attached by HTTPRecord.MarshalJSON. Both
// decisions follow from the same fact — these describe the HOST, not the
// record:
//
//   - Storing them per row would put many identical copies of one answer in the
//     database (a sweep writes several records per host; a redirect chain alone
//     is three), and they are stale the moment their TTL passes. Only the single
//     `ip` column is persisted.
//   - Attaching them inside MarshalJSON would decorate every record that every
//     caller in the process serializes from a global cache. The ingest server
//     marshals `[]*HTTPRecord` straight to the HTTP response, so one project's
//     rows would carry a name resolved at an unknown time while ingesting
//     another's.
//
// So the emit sites that KNOW this process did the probing opt in, and everyone
// else keeps serializing a record as itself.
type HostFacts struct {
	A     []string       `json:"a,omitempty"`
	AAAA  []string       `json:"aaaa,omitempty"`
	CNAME []string       `json:"cname,omitempty"`
	TLS   *tlsprobe.Info `json:"tls,omitempty"`
}

// Empty reports whether this process observed nothing for the host. Empty facts
// are omitted entirely rather than emitted as empty arrays: "not probed" and "no
// records" are different answers.
func (h HostFacts) Empty() bool {
	return len(h.A) == 0 && len(h.AAAA) == 0 && len(h.CNAME) == 0 && h.TLS == nil
}

// LookupHostFacts returns what this PROCESS observed for a record's host, or
// zero facts when it observed nothing (a run without --tls-probe, a plaintext
// endpoint, or any process that did no probing — an `export` of an old database,
// for instance).
func LookupHostFacts(hostname string, port int) HostFacts {
	a, aaaa, cname := CachedDNS(hostname)
	return HostFacts{A: a, AAAA: aaaa, CNAME: cname, TLS: tlsprobe.Cached(hostname, port)}
}

// AsMap renders the facts as JSON keys, for the map-shaped agent views. Keys
// match httpx's names, and match the struct tags above — one definition of the
// key set, so the two output shapes cannot drift.
func (h HostFacts) AsMap() map[string]any {
	if h.Empty() {
		return nil
	}
	raw, err := json.Marshal(h)
	if err != nil {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// HostFactsFieldNames are the JSON keys AsMap can produce, for the --fields
// allowlist. Derived from the struct so a new fact reaches the allowlist with
// its emitter.
var HostFactsFieldNames = []string{"a", "aaaa", "cname", "tls"}

// RecordWithHostFacts is an HTTPRecord serialized together with its host facts.
// Marshals as the record's own object with the fact keys merged in at the top
// level, which is where httpx puts them and therefore where a consumer written
// against that output looks.
type RecordWithHostFacts struct {
	Record *HTTPRecord
	Facts  HostFacts
}

// WithHostFacts pairs a record with what this process observed about its host.
// Returns the bare record when nothing was observed, so a run that probed
// nothing emits exactly the bytes it always did.
func WithHostFacts(r *HTTPRecord) any {
	if r == nil {
		return r
	}
	facts := LookupHostFacts(r.Hostname, r.Port)
	if facts.Empty() {
		return r
	}
	return RecordWithHostFacts{Record: r, Facts: facts}
}

// MarshalJSON merges the fact keys into the record's own object rather than
// nesting them under a wrapper, so the emitted shape is the record a consumer
// already parses plus the extra keys.
func (rw RecordWithHostFacts) MarshalJSON() ([]byte, error) {
	recordJSON, err := json.Marshal(rw.Record)
	if err != nil {
		return nil, err
	}
	factsJSON, err := json.Marshal(rw.Facts)
	if err != nil {
		return nil, err
	}
	// Both are objects; splice the facts' fields in before the record's closing
	// brace. Cheaper and lossless compared with decoding the record into a map
	// and re-encoding it, which would reorder keys and round-trip every body.
	if len(factsJSON) <= 2 || len(recordJSON) <= 2 {
		return recordJSON, nil
	}
	out := make([]byte, 0, len(recordJSON)+len(factsJSON))
	out = append(out, recordJSON[:len(recordJSON)-1]...)
	out = append(out, ',')
	out = append(out, factsJSON[1:len(factsJSON)-1]...)
	out = append(out, '}')
	return out, nil
}
