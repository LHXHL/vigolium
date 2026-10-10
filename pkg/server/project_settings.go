package server

import (
	"fmt"

	"github.com/vigolium/vigolium/internal/config"
)

// settingsForProject returns a private copy of the server's settings with
// projectUUID's config overlay (config.ProjectConfigPath) applied: the global →
// project layers of the precedence every scan entry point shares. The caller
// layers the request's scanning profile and fields on top, and may mutate the
// result freely.
//
// The copy is deep (config.CloneSettings): ApplyProfile decodes YAML through
// existing pointers and into existing maps, so overlaying onto a shallow copy
// would write one project's values into h.settings and every later request.
// It is taken under the config watcher's read lock so a hot reload cannot tear
// it.
//
// Nothing merged is cached, because h.settings changes under the server (API
// config writes, hot reload). The parsed overlay is cached per project by
// config.ApplyProjectOverlay and revalidated against the file on every call, so
// a `scope set --project` from the CLI applies to the next REST scan without a
// restart.
func (h *Handlers) settingsForProject(projectUUID string) (*config.Settings, error) {
	var settings *config.Settings
	if h.settings == nil {
		settings = config.DefaultSettings()
	} else {
		h.configWatcher.RLock()
		settings = config.CloneSettings(h.settings)
		h.configWatcher.RUnlock()
	}
	if err := config.ApplyProjectOverlay(settings, projectUUID); err != nil {
		return nil, fmt.Errorf("project config: %w", err)
	}
	return settings, nil
}
