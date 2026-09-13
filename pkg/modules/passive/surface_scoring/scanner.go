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

	// maxTrackedHosts limits how many distinct hosts are buffered concurrently.
	maxTrackedHosts = 1000
)

// bufferedEntry is one record awaiting the host-scoped signal. It holds only a
// request hash and a bitmask — no response bodies are retained past
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

// Module implements a passive module that scores each HTTP record on how much
// attack surface it represents and writes the score to http_records.surface_score.
//
// Scoring is split across two phases on purpose. The four record-scoped signals
// are computed in ScanPerRequest, where the response is in hand. The host-scoped
// SignalTechStack is resolved in Flush, because under ParallelPassive every
// eligible passive module for one record runs concurrently: reading the tech
// registry during ScanPerRequest would race the fingerprint module that
// populates it, and the record that first reveals a host's stack would score
// itself as if the host had none.
//
// The consequence is that nothing is written until end-of-scan. A scan that is
// interrupted before the executor's flush leaves scores at 0, which reads
// correctly as "not scored" rather than as "no surface".
type Module struct {
	modkit.BasePassiveModule

	mu      sync.Mutex
	buffers map[string][]bufferedEntry // key: registry host key (hostname[:port])
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
// record's UUID. It emits no findings — the score is record metadata.
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
	// per-record cost — body scans, regexes, insertion-point work — only for the
	// result to be dropped on the floor a few lines below.
	if !m.admits(host) {
		return nil, nil
	}

	signals := recordSignals(ctx, host, scanCtx)

	m.mu.Lock()
	defer m.mu.Unlock()
	// Re-checked under the lock: admits() released it, so a concurrent worker may
	// have taken the last slot. Overshooting by a few entries would be harmless,
	// but the check is one map lookup.
	buf, exists := m.buffers[host]
	if !exists && len(m.buffers) >= maxTrackedHosts {
		return nil, nil
	}
	if len(buf) >= maxRecordsPerHost {
		return nil, nil
	}
	m.buffers[host] = append(buf, bufferedEntry{requestHash: ctx.Request().ID(), signals: signals})

	return nil, nil
}

// admits reports whether the buffer has room for another record on host.
func (m *Module) admits(host string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	buf, exists := m.buffers[host]
	if !exists {
		return len(m.buffers) < maxTrackedHosts
	}
	return len(buf) < maxRecordsPerHost
}

// Flush implements modules.Flusher. Called once after all workers finish, so
// every fingerprint module has published its detections by now and the
// host-scoped tech signal can be resolved without racing them. It is also when
// each buffered request hash is resolved to a record UUID — the rows are written
// asynchronously, so most do not exist yet while ScanPerRequest is running.
func (m *Module) Flush(scanCtx *modkit.ScanContext) {
	m.mu.Lock()
	buffers := m.buffers
	m.buffers = make(map[string][]bufferedEntry)
	m.mu.Unlock()

	if scanCtx == nil || scanCtx.SurfaceScoreUpdater == nil ||
		scanCtx.RequestUUIDResolver == nil || len(buffers) == 0 {
		return
	}

	total := 0
	for _, entries := range buffers {
		total += len(entries)
	}
	// Sized up front: this map can reach the full buffered count, and growing it
	// from zero at end of scan means ~19 rehash-and-copy passes on the critical
	// path between the last worker finishing and the scan reporting done.
	scores := make(map[string]int, total)

	for host, entries := range buffers {
		hostSignals := Signal(0)
		if scanCtx.TechStack.HostKnown(host) {
			hostSignals |= SignalTechStack
		}
		for _, entry := range entries {
			uuid := scanCtx.RequestUUIDResolver.ResolveRequestUUID(entry.requestHash)
			if uuid == "" {
				// The record was never persisted — there is no row to score.
				continue
			}
			scores[uuid] = (entry.signals | hostSignals).Score()
		}
	}

	if len(scores) == 0 {
		return
	}

	if err := scanCtx.SurfaceScoreUpdater.UpdateSurfaceScores(context.Background(), scores); err != nil {
		zap.L().Debug("surface_scoring: failed to update surface scores", zap.Error(err))
	}
}
