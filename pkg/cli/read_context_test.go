package cli

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

func resetReadContext(t *testing.T) {
	t.Helper()
	globalGlobDB, globalStateless, globalReadOnly = "", false, false
	globalProjectUUID, globalProjectName, globalConfig = "", "", ""
	dbPathEnvAutoStateless = false
	clicommon.SetOpenedDBPath("")
	t.Cleanup(func() {
		globalGlobDB, globalStateless, globalReadOnly = "", false, false
		globalProjectUUID, globalProjectName, globalConfig = "", "", ""
		dbPathEnvAutoStateless = false
		clicommon.SetOpenedDBPath("")
	})
}

// Finding IDs are per-database autoincrement integers, so a follow-up that omits
// the database resolves the same id in a DIFFERENT store. Every generated query
// omitted it.
func TestFollowUpQueryCarriesTheDatabase(t *testing.T) {
	resetReadContext(t)
	clicommon.SetOpenedDBPath("/engagements/acme.sqlite")

	got := followUpQuery("finding", "--id", "5", "--json")
	if !strings.Contains(got, "--db /engagements/acme.sqlite") {
		t.Errorf("follow-up must pin the store it was read from, got: %s", got)
	}
}

func TestFollowUpQueryCarriesScope(t *testing.T) {
	resetReadContext(t)
	clicommon.SetOpenedDBPath("/tmp/x.sqlite")
	globalStateless = true

	got := followUpQuery("finding", "--id", "5")
	if !strings.Contains(got, "--stateless") {
		t.Errorf("a project-unscoped read must stay unscoped on the follow-up, got: %s", got)
	}

	resetReadContext(t)
	clicommon.SetOpenedDBPath("/tmp/x.sqlite")
	globalProjectUUID = "proj-b"
	got = followUpQuery("finding", "--id", "5")
	// Carried explicitly rather than left to the active-project file, which is
	// global state a parallel caller may have changed between the two reads.
	if !strings.Contains(got, "--project-uuid proj-b") {
		t.Errorf("the selected project must be pinned explicitly, got: %s", got)
	}
	if strings.Contains(got, "--stateless") {
		t.Errorf("a scoped read must not advertise itself as unscoped, got: %s", got)
	}
}

func TestFollowUpQueryQuotesPathsWithSpaces(t *testing.T) {
	resetReadContext(t)
	clicommon.SetOpenedDBPath("/tmp/db with space.sqlite")

	got := followUpQuery("finding", "--id", "5")
	if !strings.Contains(got, "'/tmp/db with space.sqlite'") {
		t.Errorf("a path with a space must be quoted, got: %s", got)
	}
}

// A glob merge reads through a temporary database that is removed when the
// process exits. No argument list reopens it, so the honest answer is no
// follow-up rather than one that silently resolves the id somewhere else.
func TestFollowUpQuerySuppressedForAGlobMerge(t *testing.T) {
	resetReadContext(t)
	globalGlobDB = "/scans/*.sqlite"
	clicommon.SetOpenedDBPath("/tmp/scratch-9271.sqlite")

	if got := followUpQuery("finding", "--id", "5"); got != "" {
		t.Errorf("a merged read cannot be reproduced; follow-up must be empty, got: %s", got)
	}
	if _, ok := readContextArgs(); ok {
		t.Error("readContextArgs must report that the read is not reproducible")
	}
}

func TestFollowUpQueryCarriesReadOnlyAndConfig(t *testing.T) {
	resetReadContext(t)
	clicommon.SetOpenedDBPath("/tmp/x.sqlite")
	globalReadOnly = true
	globalConfig = "/etc/vigolium.yaml"

	got := followUpQuery("traffic", "--uuid", "abc")
	for _, want := range []string{"--read-only", "--config /etc/vigolium.yaml"} {
		if !strings.Contains(got, want) {
			t.Errorf("follow-up missing %q, got: %s", want, got)
		}
	}
}

func TestFollowUpQueryStartsWithTheBinaryName(t *testing.T) {
	resetReadContext(t)
	clicommon.SetOpenedDBPath("/tmp/x.sqlite")

	got := followUpQuery("finding", "--id", "5")
	if !strings.HasPrefix(got, "vigolium ") {
		t.Errorf("follow-up must be runnable as written, got: %s", got)
	}
}
