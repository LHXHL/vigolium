package database

import (
	"context"
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

// hostEndpoint identifies one endpoint. A comparable struct rather than a
// formatted "host|port" string: it is built on every lookup, before the memo is
// consulted, so a string key would allocate once per emitted record.
type hostEndpoint struct {
	host string // normalized by dnsKey, so writer and reader cannot key differently
	port int
}

// endpointFacts is one memoized answer plus its rendered map form. AsMap round
// trips through JSON, and the agent views call it per RECORD, so caching it with
// the facts makes that cost per distinct ENDPOINT instead.
type endpointFacts struct {
	facts HostFacts
	asMap map[string]any
}

// StoredHostFacts serves a run's persisted observations, falling back to the
// process caches.
//
// The fallback order is deliberate. The stored row is the durable answer and
// survives both cache eviction and the process; the caches can still be ahead of
// it for an endpoint observed after the observations were written. Preferring
// the stored row means a large sweep emits the same facts for its first host as
// for its last, which the caches alone could not do: they hold 8192 entries and
// evict in insertion order, so on a bigger sweep the hosts resolved EARLIEST had
// their answers dropped before the export that wanted them.
//
// Resolution is LAZY and memoized: one query per distinct endpoint the caller
// actually asks about, not a preload of the run's observations. See
// Repository.LookupHostObservation for why preloading was the wrong shape.
//
// Every method is nil-receiver safe and a nil *StoredHostFacts behaves as
// "process caches only", so callers never branch on it.
type StoredHostFacts struct {
	ctx         context.Context
	repo        *Repository
	projectUUID string
	scanUUID    string

	// available is false when the database predates the table, which makes every
	// lookup a straight fall-through to the process caches.
	available bool

	// memo holds one entry per endpoint asked about, so a corpus with many
	// records on few hosts issues few queries. Bounded by distinct endpoints
	// emitted - the same order as the URL-dedup set the export already keeps, so
	// it adds no new class of growth.
	memo map[hostEndpoint]endpointFacts

	// stored and missing partition what the lookups found, for reporting.
	// HostFacts.Empty() collapses three different states - never probed, probed
	// and genuinely empty, and probed then lost - and only counting them tells an
	// operator their output is incomplete rather than their hosts uninteresting.
	stored  int
	missing int
}

// NewStoredHostFacts prepares an endpoint-fact reader for an emit pass. A nil
// repo, or a database predating the observations table, yields a reader that
// answers from the process caches alone.
func NewStoredHostFacts(ctx context.Context, repo *Repository, projectUUID, scanUUID string) *StoredHostFacts {
	s := &StoredHostFacts{
		ctx:         ctx,
		repo:        repo,
		projectUUID: projectUUID,
		scanUUID:    scanUUID,
		memo:        make(map[hostEndpoint]endpointFacts),
	}
	s.available = repo.HasHostObservations(ctx)
	return s
}

// Facts returns what was observed about one endpoint.
func (s *StoredHostFacts) Facts(hostname string, port int) HostFacts {
	return s.resolve(hostname, port).facts
}

// FactsMap is Facts rendered as JSON keys for the map-shaped agent views,
// memoized alongside the facts so the render cost is per endpoint, not per
// record.
func (s *StoredHostFacts) FactsMap(hostname string, port int) map[string]any {
	return s.resolve(hostname, port).asMap
}

func (s *StoredHostFacts) resolve(hostname string, port int) endpointFacts {
	if s == nil {
		facts := LookupHostFacts(hostname, port)
		return endpointFacts{facts: facts, asMap: facts.AsMap()}
	}
	key := hostEndpoint{host: dnsKey(hostname), port: port}
	if key.host == "" {
		return endpointFacts{}
	}
	if hit, ok := s.memo[key]; ok {
		return hit
	}

	var facts HostFacts
	if s.available {
		stored, err := s.repo.LookupHostObservation(s.ctx, s.projectUUID, s.scanUUID, key.host, port)
		if err != nil {
			// One endpoint's lookup failing must not abort the emit or silently
			// pass as "this host had nothing": stop querying and let the rest of
			// the pass fall through to the caches, which MissingCount then counts.
			s.available = false
		} else {
			facts = stored
		}
	}
	// Not stored: the process may still have it in cache - an endpoint observed
	// after the observations were written, or a run that stored none.
	if facts.Empty() {
		facts = LookupHostFacts(key.host, port)
	}

	if facts.Empty() {
		s.missing++
	} else {
		s.stored++
	}
	// Memoized even when empty, so an endpoint nothing knows about is queried
	// once rather than once per record that mentions it.
	hit := endpointFacts{facts: facts, asMap: facts.AsMap()}
	s.memo[key] = hit
	return hit
}

// MissingCount is how many distinct endpoints this pass could describe from
// neither the stored observations nor the process caches.
func (s *StoredHostFacts) MissingCount() int {
	if s == nil {
		return 0
	}
	return s.missing
}

// Stored reports how many distinct endpoints this pass could describe.
func (s *StoredHostFacts) Stored() int {
	if s == nil {
		return 0
	}
	return s.stored
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

// WithFacts pairs a record with what src observed about its host. Returns the
// bare record when nothing was observed, so a process that probed nothing emits
// exactly the bytes it always did. A nil src answers from the process caches.
func WithFacts(src *StoredHostFacts, r *HTTPRecord) any {
	if r == nil {
		return r
	}
	facts := src.Facts(r.Hostname, r.Port)
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
	// Appended onto recordJSON's own buffer rather than a fresh one. Marshal
	// returns a buffer this function owns, and a record carries its raw
	// request/response, so copying it a second time to prepend it to itself was
	// the largest allocation on the export path.
	out := append(recordJSON[:len(recordJSON)-1], ',')
	out = append(out, factsJSON[1:len(factsJSON)-1]...)
	out = append(out, '}')
	return out, nil
}
