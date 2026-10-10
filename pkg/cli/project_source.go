package cli

import (
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

// Where the project a command ran against came from. Rendered as
// `project_source` on every -j envelope.
//
// The active-project file (~/.vigolium/active-project, written by `project
// use`) is global to the user: one agent's `project use` silently re-scopes
// every other shell and agent that has not pinned a project. Provenance on the
// envelope is what lets a consumer notice that, and the warning below is what
// tells it how to stop depending on it.
const (
	projectSourceFlag       = "flag"
	projectSourceEnv        = "env"
	projectSourceActiveFile = "active_file"
	projectSourceDefault    = "default"
)

// activeFileProjectWarning is added to a -j envelope whose project was resolved
// from the global active-project file.
const activeFileProjectWarning = "project resolved from the global active-project file (set by `vigolium project use`, shared by every shell); pin --project-uuid or VIGOLIUM_PROJECT_UUID"

// currentProjectSource reports where this process's project selection comes
// from, and whether the active-project file actually scoped the work.
//
// When resolution ran, its branch is the answer. When it did not (the command
// never needed a project), the answer is what resolution WOULD pick, worked out
// without opening a database: a flag or env selection, else the active file if
// one is set, else the default.
func currentProjectSource() (source string, resolvedFromActiveFile bool) {
	selection := func() string {
		if projectFromEnv {
			return projectSourceEnv
		}
		return projectSourceFlag
	}
	if branch, ok := clicommon.ProjectResolutionBranch(); ok {
		switch branch {
		case clicommon.BranchSelection:
			return selection(), false
		case clicommon.BranchActiveFile:
			return projectSourceActiveFile, true
		default:
			return projectSourceDefault, false
		}
	}
	if globalProjectUUID != "" || globalProjectName != "" {
		return selection(), false
	}
	if persisted, err := config.ReadActiveProject(); err == nil && persisted != "" {
		return projectSourceActiveFile, false
	}
	return projectSourceDefault, false
}

// attachProjectSource stamps project_source on env, and the active-file
// warning when that file scoped the work. A command's own `warnings` extra
// (auth lint's count) is left alone.
func attachProjectSource(env *agentEnvelope) {
	source, fromActiveFile := currentProjectSource()
	env.With("project_source", source)
	if fromActiveFile {
		if _, taken := env.extra["warnings"]; !taken {
			env.With("warnings", []string{activeFileProjectWarning})
		}
	}
}
