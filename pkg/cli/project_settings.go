package cli

import (
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

// overlayProjectUUID returns the project whose config overlay
// (config.ProjectConfigPath) applies to this invocation's settings, or "" for
// global-only settings.
//
// It follows the same rule as project-scoped reads (effectiveProjectUUID): a
// standalone database — -S/--stateless, --glob-db, or a shell pinned with
// $VIGOLIUM_DB_PATH — runs unscoped, so the persisted active project (a
// different context from the pinned session) contributes no overlay. Naming a
// project (--project-uuid / --project-name or their env vars) applies its
// overlay in every mode.
func overlayProjectUUID() (string, error) {
	if (statelessReadRequested() || dbPathEnvPinned) && !explicitProjectSelected() {
		return "", nil
	}
	return resolveProjectUUID()
}

// loadProjectSettings loads the settings a scan (or a scope judgement) runs
// under: global config, then the invocation's project overlay. The scanning
// profile and CLI flags are layered on afterwards by the scan-options
// resolver, completing global → project → profile → CLI.
func loadProjectSettings(configPath string) (*config.Settings, error) {
	projectUUID, err := overlayProjectUUID()
	if err != nil {
		return nil, err
	}
	return clicommon.LoadProjectSettings(configPath, projectUUID)
}
