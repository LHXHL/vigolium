package cli

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/internal/scratch"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/olium/tool"
	"go.uber.org/zap"
)

// The environment of the commands an agent's bash tool runs.
//
// The operator agent drives vigolium by shelling out to it (`vigolium finding
// -j`, `vigolium scan-url …`). Those children used to inherit only the process
// environment and resolve everything again on their own: `vigolium` was
// whatever a login shell's PATH found first (often a different install), the
// database was the default one unless the run was -S, and the project was the
// global active-project file. A child of `agent autopilot --db acme.sqlite
// --project-uuid P` therefore read the default database's default project and
// reported someone else's findings as this run's.
//
// agentChildEnv pins each of those to what this process resolved:
//
//	PATH                   a scratch dir holding a `vigolium` symlink to this
//	                       executable, prepended (more precise than prepending
//	                       the executable's own directory, which may hold other
//	                       binaries)
//	VIGOLIUM_BIN           the executable's absolute path
//	VIGOLIUM_DB            the database this process opened, exactly as --db
//	                       would pass it: project scoping stays on
//	VIGOLIUM_DB_PATH       instead of VIGOLIUM_DB, only when this process itself
//	                       reads unscoped (-S, or it was pinned by
//	                       VIGOLIUM_DB_PATH): that variable also turns project
//	                       scoping off for reads, which would silently widen a
//	                       scoped parent's children to every project in the file
//	VIGOLIUM_PROJECT_UUID  the resolved project (scoped parents only)
//	VIGOLIUM_CONFIG        the --config file, when one was given
//
// The bash tool runs `bash -c` (not a login shell) so a profile cannot reorder
// PATH behind this.

// Child environment variable names. dbPathEnvVar is VIGOLIUM_DB_PATH.
const (
	dbEnvVar        = "VIGOLIUM_DB"
	configEnvVar    = "VIGOLIUM_CONFIG"
	binEnvVar       = "VIGOLIUM_BIN"
	projectUUIDEnv  = "VIGOLIUM_PROJECT_UUID"
	projectNameEnv  = "VIGOLIUM_PROJECT_NAME"
	childBinDirName = "vigolium-bin-*"
)

// agentChildDBUnscoped is set by beginAgentStateless: the run writes into a
// throwaway database whose children read it unscoped (VIGOLIUM_DB_PATH).
var agentChildDBUnscoped bool

// installAgentChildEnv installs the bash tool's environment builder for this
// process. Called by every agent command that runs the olium tools (query,
// triage, swarm, autopilot, olium); idempotent. The server does not call it:
// its runs belong to the project of each request, not to the process.
func installAgentChildEnv() {
	tool.SetBashEnvBuilder(agentChildEnv)
}

var (
	childBinOnce sync.Once
	childBinDir  string
	childBinPath string
)

// agentChildBin returns the directory holding the `vigolium` symlink and the
// executable it points at. When the symlink cannot be made, the directory is
// the executable's own (still ahead of a profile's PATH).
func agentChildBin() (dir, exe string) {
	childBinOnce.Do(func() {
		self, err := os.Executable()
		if err != nil {
			zap.L().Debug("agent child env: cannot resolve own executable", zap.Error(err))
			return
		}
		if resolved, rerr := filepath.EvalSymlinks(self); rerr == nil {
			self = resolved
		}
		childBinPath = self
		childBinDir = filepath.Dir(self)
		tmp, err := scratch.MkdirTemp(childBinDirName)
		if err != nil {
			return
		}
		if err := os.Symlink(self, filepath.Join(tmp, "vigolium")); err != nil {
			zap.L().Debug("agent child env: cannot link vigolium", zap.Error(err))
			return
		}
		childBinDir = tmp
	})
	return childBinDir, childBinPath
}

// agentChildDBPath is the database a child should open: the one this process
// opened (a SQLite file), else the --db it was given. "" for a server database
// (postgres), which children reach through the config.
func agentChildDBPath() string {
	if p := strings.TrimSpace(clicommon.OpenedDBPath()); p != "" {
		if d := clicommon.OpenedDBDriver(); d == "" || d == "sqlite" {
			return absOrRaw(p)
		}
		return ""
	}
	if p := strings.TrimSpace(globalDB); p != "" {
		return absOrRaw(p)
	}
	return ""
}

// agentChildUnscoped reports whether this process reads its database with
// project scoping off, so its children should too.
func agentChildUnscoped() bool {
	return agentChildDBUnscoped || dbPathEnvPinned || statelessReadRequested()
}

// agentChildEnv builds the environment for one bash tool command.
func agentChildEnv() []string {
	drop := map[string]bool{
		"PATH": true, dbEnvVar: true, dbPathEnvVar: true, configEnvVar: true,
		binEnvVar: true, projectUUIDEnv: true, projectNameEnv: true,
	}
	env := make([]string, 0, len(os.Environ())+6)
	path := os.Getenv("PATH")
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if drop[k] {
			continue
		}
		env = append(env, kv)
	}

	dir, exe := agentChildBin()
	if dir != "" {
		path = dir + string(os.PathListSeparator) + path
	}
	env = append(env, "PATH="+path)
	if exe != "" {
		env = append(env, binEnvVar+"="+exe)
	}

	if db := agentChildDBPath(); db != "" {
		if agentChildUnscoped() {
			env = append(env, dbPathEnvVar+"="+db)
		} else {
			env = append(env, dbEnvVar+"="+db)
		}
	} else if v := os.Getenv(dbPathEnvVar); v != "" {
		// No SQLite file of our own: pass an existing pin through untouched.
		env = append(env, dbPathEnvVar+"="+v)
	}
	if !agentChildUnscoped() {
		if uuid, err := resolveProjectUUID(); err == nil && uuid != "" {
			env = append(env, projectUUIDEnv+"="+uuid)
		}
	}
	if cfg := strings.TrimSpace(globalConfig); cfg != "" {
		env = append(env, configEnvVar+"="+absOrRaw(cfg))
	}
	return env
}
