package surface_scoring

import (
	"context"
	"sync"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

const (
	// maxRecordsPerHost caps the buffer for a single host. Records past the cap
	// keep surface_score 0 (the un-scored default) rather than growing the buffer.
	maxRecordsPerHost = 500

	// maxBufferedEntries caps the module's total memory across every host.
	//
	// It replaced a per-host-count cap of 1000, which was the wrong dimension to
	// bound: a host sweep (`run probe -T hosts.txt`) buffers exactly one entry per
	// host, so a 1041-host list silently stopped scoring at host 1000 while using
	// a hundred kilobytes. Capping total entries bounds the thing that actually
	// costs memory - an entry is a request hash plus a bitmask, so 200k of them is
	// roughly 20 MB - and lets a sweep of any size score every host it reaches.
	maxBufferedEntries = 200_000
)

// bufferedEntry is one record awaiting the host-scoped signal. It holds only a
// request hash and a bitmask - no response bodies are retained past
// ScanPerRequest.
//
// The hash, not the record UUID, is what is buffered: records are persisted
// asynchronously by the record writer, so at ScanPerRequest time the row often
// does not exist yet and ResolveRequestUUID returns "". Resolving here silently
// dropped every record on a fast scan. The resolution happens in Flush, which
// runs after the writers have drained.
type bufferedEntry struct {
	requestHash string
	signals     Signal
}

// Module implements a passive module that writes the per-record surface metadata
// every other view ranks on: http_records.surface_score, and the host's detected
// stack in http_records.technology.
//
// Scoring is split across two phases on purpose. The record-scoped signals are
// computed in ScanPerRequest, where the response is in hand. The host-scoped
// SignalTechStack - and the technology column it comes from - is resolved in
// Flush, because under ParallelPassive every eligible passive module for one
// record runs concurrently: reading the tech registry during ScanPerRequest
// would race the fingerprint module that populates it, and the record that first
// reveals a host's stack would score itself as if the host had none.
//
// The consequence is that nothing is written until end-of-scan. A scan that is
// interrupted before the executor's flush leaves scores at 0, which reads
// correctly as "not scored" rather than as "no surface".
type Module struct {
	modkit.BasePassiveModule

	mu      sync.Mutex
	buffers map[string][]bufferedEntry // key: registry host key (hostname[:port])
	// buffered is the running total across every host, checked against
	// maxBufferedEntries. Kept as a counter rather than summed on demand because
	// admits() runs on every record and would otherwise walk every host.
	buffered int
}

// New creates a new surface scoring passive module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		buffers: make(map[string][]bufferedEntry),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest computes the record-scoped signals and buffers them against the
// record's UUID. It emits no findings - the score is record metadata.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if scanCtx == nil || scanCtx.SurfaceScoreUpdater == nil || scanCtx.RequestUUIDResolver == nil {
		return nil, nil
	}
	if ctx == nil || ctx.Response() == nil || ctx.Request() == nil {
		return nil, nil
	}

	host := modkit.RegistryHostKey(ctx)
	if host == "" {
		return nil, nil
	}

	// Test the caps BEFORE scoring. A corpus is typically a handful of hosts, so
	// once a host fills its budget every later record would otherwise pay the full
	// per-record cost - body scans, regexes, insertion-point work - only for the
	// result to be dropped on the floor a few lines below.
	if !m.admits(host) {
		return nil, nil
	}

	signals := recordSignals(ctx, host, scanCtx)

	m.mu.Lock()
	defer m.mu.Unlock()
	// Re-checked under the lock: admits() released it, so a concurrent worker may
	// have taken the last slot. Overshooting by a few entries would be harmless,
	// but the check is two integer comparisons.
	if m.buffered >= maxBufferedEntries {
		return nil, nil
	}
	buf := m.buffers[host]
	if len(buf) >= maxRecordsPerHost {
		return nil, nil
	}
	m.buffers[host] = append(buf, bufferedEntry{requestHash: ctx.Request().ID(), signals: signals})
	m.buffered++

	return nil, nil
}

// admits reports whether the buffer has room for another record on host.
func (m *Module) admits(host string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.buffered < maxBufferedEntries && len(m.buffers[host]) < maxRecordsPerHost
}

// Flush implements modules.Flusher. Called once after all workers finish, so
// every fingerprint module has published its detections by now and the
// host-scoped tech signal can be resolved without racing them. It is also when
// each buffered request hash is resolved to a record UUID - the rows are written
// asynchronously, so most do not exist yet while ScanPerRequest is running.
//
// It writes two columns, both derived from the same host-to-records map:
// surface_score, and technology.
//
// The technology write lives here rather than in the fingerprint modules
// themselves because the registry is host-scoped while the column is
// record-scoped, and only this point in the scan knows both halves: which
// records belong to which host (buffered during ScanPerRequest) and what the
// full set of 26 fingerprint modules concluded about that host (settled only
// once every worker has exited). Doing it in each fingerprint module would mean
// 26 modules racing to overwrite one column with a partial view.
func (m *Module) Flush(scanCtx *modkit.ScanContext) {
	m.mu.Lock()
	buffers := m.buffers
	m.buffers = make(map[string][]bufferedEntry)
	m.buffered = 0
	m.mu.Unlock()

	if scanCtx == nil || scanCtx.SurfaceScoreUpdater == nil ||
		scanCtx.RequestUUIDResolver == nil || len(buffers) == 0 {
		return
	}

	total := 0
	for _, entries := range buffers {
		total += len(entries)
	}
	// Sized up front: this map reaches the full buffered count, and growing it
	// from zero at end of scan means ~19 rehash-and-copy passes on the critical
	// path between the last worker finishing and the scan reporting done.
	scores := make(map[string]int, total)
	// Deliberately NOT pre-sized. Only records on a fingerprinted host land here,
	// which is a subset and frequently none at all - sizing it to total reserved
	// ~12 MB at the buffer cap to hold, in the common case, nothing.
	technology := make(map[string][]string)

	for host, entries := range buffers {
		hostSignals := Signal(0)
		hostTech := scanCtx.TechStack.Tags(host)
		if len(hostTech) > 0 {
			hostSignals |= SignalTechStack
		}
		for _, entry := range entries {
			uuid := scanCtx.RequestUUIDResolver.ResolveRequestUUID(entry.requestHash)
			if uuid == "" {
				// The record was never persisted - there is no row to score.
				continue
			}
			scores[uuid] = (entry.signals | hostSignals).Score()
			if len(hostTech) > 0 {
				// Every record on this host shares the one slice; the repository
				// groups by value before writing, so nothing copies it per record.
				technology[uuid] = hostTech
			}
		}
	}

	if len(scores) == 0 {
		return
	}

	if err := scanCtx.SurfaceScoreUpdater.UpdateSurfaceScores(context.Background(), scores); err != nil {
		zap.L().Debug("surface_scoring: failed to update surface scores", zap.Error(err))
	}

	if scanCtx.TechAnnotator != nil && len(technology) > 0 {
		if err := scanCtx.TechAnnotator.SetRecordTechnology(context.Background(), technology); err != nil {
			zap.L().Debug("surface_scoring: failed to set record technology", zap.Error(err))
		}
	}
}
