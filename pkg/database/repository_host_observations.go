package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"
)

// hostObservationBatchSize bounds one insert transaction. A sweep can observe
// tens of thousands of endpoints, and handing them to the driver as a single
// statement builds one enormous query string in memory for no gain - these rows
// are small and there is nothing to gain past a few hundred per round trip.
const hostObservationBatchSize = 500

// HostObservationInput is one endpoint's observation, as the probe collects it,
// before it becomes a row.
//
// HostFacts is embedded rather than restated: the answer being stored IS the
// answer that will later be emitted, and copying its fields here meant two
// places to edit for every new fact and two Empty() methods that could silently
// disagree. What this type adds is the two things HostFacts cannot carry -
// which endpoint the answer describes, and whether the lookup finished.
type HostObservationInput struct {
	Hostname string
	Port     int
	HostFacts

	// Complete reports that the lookup ran to an answer. A cut-short prefetch
	// records incomplete observations rather than none, so a later reader can
	// tell "no AAAA record" from "we never got there".
	Complete bool
}

// Empty reports whether the observation carries nothing worth storing. A row
// with no answer AND no completeness claim states nothing that the absence of a
// row does not already state.
func (o HostObservationInput) Empty() bool {
	return o.HostFacts.Empty() && !o.Complete
}

// SaveHostObservations persists a run's host observations in bounded batches.
//
// ON CONFLICT (scan_uuid, hostname, port) updates rather than inserting: within
// ONE run an endpoint has one observation, so a second write for it is a
// refinement (the TLS handshake finishing after the DNS answer, say) and not a
// second event. ACROSS runs the conflict cannot fire, which is the point -
// re-probing a host next month adds that month's observation and leaves this
// one intact.
func (r *Repository) SaveHostObservations(ctx context.Context, projectUUID, scanUUID string, obs []HostObservationInput) error {
	if r == nil || r.db == nil || len(obs) == 0 {
		return nil
	}
	project := defaultProjectUUID(projectUUID)
	now := time.Now().UTC()

	rows := make([]HostObservation, 0, len(obs))
	for _, o := range obs {
		// dnsKey, not an inline ToLower+TrimSpace: it owns the hostname
		// normalization rule, and a writer that normalized differently from a
		// reader would make a stored answer invisible to the caller that wanted it.
		host := dnsKey(o.Hostname)
		if host == "" || o.Empty() {
			continue
		}
		rows = append(rows, HostObservation{
			ProjectUUID: project,
			ScanUUID:    scanUUID,
			Hostname:    host,
			Port:        o.Port,
			ObservedAt:  now,
			DNSA:        o.A,
			DNSAAAA:     o.AAAA,
			DNSCNAME:    o.CNAME,
			TLS:         o.TLS,
			Complete:    o.Complete,
		})
	}

	// Chunked with slices.Chunk, the same way deleteRecordsByUUIDsTx bounds its
	// statements: a sweep can observe tens of thousands of endpoints, and one
	// statement for all of them builds an enormous query string for no gain.
	for chunk := range slices.Chunk(rows, hostObservationBatchSize) {
		if _, err := r.db.NewInsert().Model(&chunk).
			On("CONFLICT (scan_uuid, hostname, port) DO UPDATE").
			Set("observed_at = EXCLUDED.observed_at").
			Set("dns_a = EXCLUDED.dns_a").
			Set("dns_aaaa = EXCLUDED.dns_aaaa").
			Set("dns_cname = EXCLUDED.dns_cname").
			Set("tls = EXCLUDED.tls").
			Set("complete = EXCLUDED.complete").
			Exec(ctx); err != nil {
			return fmt.Errorf("save host observations: %w", err)
		}
	}
	return nil
}

// HasHostObservations reports whether this database can answer endpoint lookups
// at all.
//
// A database written before this table existed has nothing stored, which is a
// fact about it and not a failure. Asked once up front so a read of an older
// file degrades to the cache-only behaviour silently, instead of failing a query
// per endpoint about a table it was never going to have. A read-only handle
// cannot be migrated into having one either, and missingColumns only tracks
// ALTER-added columns, never whole tables.
func (r *Repository) HasHostObservations(ctx context.Context) bool {
	if r == nil || r.db == nil {
		return false
	}
	return r.db.tableExists(ctx, "host_observations")
}

// LookupHostObservation returns the observation for one endpoint, or zero facts
// when none is stored.
//
// One endpoint per call, rather than loading a run's observations up front.
// Preloading looked right for a streaming emit path - fetch once, then answer
// every record from memory - and was wrong in both directions. This table
// accumulates a row per endpoint per RUN, so the project-wide preload returned
// endpoints × runs rows to build a map of endpoints: on 20k endpoints across 25
// runs, exporting a two-record database peaked at 842 MB against a 120 MB
// baseline, with export memory growing in scan history rather than in the corpus
// being exported. Resolving "latest per endpoint" in SQL instead still cost a
// full scan and a temp b-tree. And a paginated reader (`traffic -j`, 100 rows)
// paid all of it to ask about a handful of hosts.
//
// A point lookup is index-only against idx_host_obs_project_host_id, and the
// caller memoizes, so the cost is one query per DISTINCT endpoint actually
// emitted and the memory is one entry per the same.
//
// scanUUID empty widens the read to the whole project and takes the most
// recently RECORDED observation - the right answer for `export` of a database
// whose runs this process did not perform.
func (r *Repository) LookupHostObservation(ctx context.Context, projectUUID, scanUUID, hostname string, port int) (HostFacts, error) {
	if r == nil || r.db == nil || hostname == "" {
		return HostFacts{}, nil
	}
	row := new(HostObservation)
	q := r.db.NewSelect().Model(row).
		Where("project_uuid = ?", defaultProjectUUID(projectUUID)).
		Where("hostname = ?", dnsKey(hostname)).
		Where("port = ?", port)
	if scanUUID != "" {
		// One scan holds at most one observation per endpoint (the unique index),
		// so this is already a single row - no ordering needed, and asking for one
		// would make SQLite open a sorter to order a single row.
		q = q.Where("scan_uuid = ?", scanUUID)
	} else {
		// Highest id, not latest observed_at: id is the insertion order, so this
		// is "most recently recorded", which is well-defined even when two runs
		// stamp the same timestamp.
		q = q.Order("id DESC")
	}
	if err := q.Limit(1).Scan(ctx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return HostFacts{}, nil
		}
		return HostFacts{}, fmt.Errorf("lookup host observation: %w", err)
	}
	return row.Facts(), nil
}

// Facts renders a stored observation back into the output shape. The columns are
// bun jsonb fields, so this is a field copy rather than a decode.
func (o *HostObservation) Facts() HostFacts {
	return HostFacts{A: o.DNSA, AAAA: o.DNSAAAA, CNAME: o.DNSCNAME, TLS: o.TLS}
}
