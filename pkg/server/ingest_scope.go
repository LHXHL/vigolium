package server

import (
	"errors"
	"os"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/storagesig"
)

// ingestScope is the scope a recorded request is judged by before it is
// stored: the project's matcher and whether its rules apply on ingest. The
// zero value admits everything.
type ingestScope struct {
	matcher         *config.ScopeMatcher
	appliedOnIngest bool
}

// admit reports whether rr should be stored. Static files are always filtered
// (regardless of applied_on_ingest) — except object-storage assets, kept as
// metadata-only (body stripped) so the CDN traversal modules can probe
// storage-fronted static URLs. The full scope rules apply only when
// applied_on_ingest is set.
func (s ingestScope) admit(rr *httpmsg.HttpRequestResponse) bool {
	if s.matcher == nil {
		return true
	}
	if s.matcher.IsStaticFile(rr.Request().Path()) {
		var hg storagesig.HeaderGetter
		if rr.HasResponse() && rr.Response() != nil {
			hg = rr.Response()
		}
		if !storagesig.KeepStaticAsMeta(rr.Request().Path(), hg) {
			return false
		}
		if rr.Response() != nil {
			rr.Response().TruncateBody(0) // metadata-only: keep headers, drop body
		}
	}
	if !s.appliedOnIngest {
		return true
	}
	return s.matcher.InScope(buildScopeMatchInput(rr))
}

// projectScopeEntry caches one project's overlaid ingest scope, valid while
// its overlay file keeps the recorded mtime and size.
type projectScopeEntry struct {
	gen     uint64 // Handlers.scopeGen when built; a scope reload invalidates it
	modTime time.Time
	size    int64
	scope   ingestScope
}

// ingestScopeFor returns the ingest scope of projectUUID: the server's scope
// with the project's config overlay (config.ApplyProjectOverlay) applied, the
// global → project precedence every scan entry point uses. A project without
// an overlay shares the server-wide cached matcher.
//
// The overlaid matcher is cached per project and rebuilt when the overlay file
// changes (a `scope set --project` from the CLI applies to the next recorded
// request without a restart) or the server's scope hot-reloads
// (resetScopeMatcher). A broken overlay is an error, never a silent fall back
// to the wider global scope.
func (h *Handlers) ingestScopeFor(projectUUID string) (ingestScope, error) {
	if h.settings == nil {
		return ingestScope{}, nil
	}
	projectUUID = strings.TrimSpace(projectUUID)
	var info os.FileInfo
	if projectUUID != "" {
		fi, err := os.Stat(config.ProjectConfigPath(projectUUID))
		switch {
		case err == nil:
			info = fi
		case !errors.Is(err, os.ErrNotExist):
			return ingestScope{}, err
		}
	}
	if info == nil {
		return ingestScope{
			matcher:         h.getScopeMatcher(),
			appliedOnIngest: h.readReloadableScope().AppliedOnIngest,
		}, nil
	}

	h.scopeMatcherMu.RLock()
	e, ok := h.projectScopes[projectUUID]
	gen := h.scopeGen
	h.scopeMatcherMu.RUnlock()
	if ok && e.gen == gen && e.size == info.Size() && e.modTime.Equal(info.ModTime()) {
		return e.scope, nil
	}

	settings, err := h.settingsForProject(projectUUID)
	if err != nil {
		return ingestScope{}, err
	}
	scope := ingestScope{
		matcher:         config.NewScopeMatcher(settings.Scope),
		appliedOnIngest: settings.Scope.AppliedOnIngest,
	}
	h.scopeMatcherMu.Lock()
	if h.projectScopes == nil {
		h.projectScopes = map[string]projectScopeEntry{}
	}
	if gen == h.scopeGen { // not invalidated while it was built
		h.projectScopes[projectUUID] = projectScopeEntry{gen: gen, modTime: info.ModTime(), size: info.Size(), scope: scope}
	}
	h.scopeMatcherMu.Unlock()
	return scope, nil
}
