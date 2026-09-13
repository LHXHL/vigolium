package cli

import (
	"strings"
)

// Every -j read attaches a ready-to-run follow-up command:
//
//	"query": "vigolium finding --id 5 --json --with-records"
//
// and every one of them was generated without the context that made the read
// reachable. Finding IDs are per-database autoincrement integers and traffic
// UUIDs are per-store, so following that string from a session pinned to
// `--db /engagements/acme.sqlite -S` opens the DEFAULT database instead and
// returns a different row with the same id, or nothing. The envelope already
// reports db_path and project_scoped; the follow-up it printed contradicted
// both.
//
// A glob merge is worse: `--glob-db '*.sqlite'` reads through a temporary
// database that is deleted when the process exits, so a follow-up naming it
// cannot be reopened by anyone, ever.
//
// readContextArgs generates the flags that reproduce the current read, and
// followUpQuery composes them with a command. The display string stays a
// display string — correctly quoted, but nobody should have to eval it.

// readContextArgs returns the flags that pin a follow-up read to the same store
// and scope as the read that produced it.
//
// Returns nil when the read cannot be reproduced (a glob merge), so the caller
// suppresses the follow-up rather than printing one that leads somewhere else.
func readContextArgs() ([]string, bool) {
	// A glob merge reads through a scratch database that does not survive the
	// process. There is no argument list that reopens it, and the honest answer
	// is no follow-up rather than a plausible one that fails or, worse, silently
	// resolves the same id in a different store.
	if strings.TrimSpace(globalGlobDB) != "" {
		return nil, false
	}

	var args []string
	if db := strings.TrimSpace(resolvedReadDBPath()); db != "" {
		args = append(args, "--db", db)
	}
	// Scope is carried explicitly rather than left to the active-project file:
	// that file is global process state a parallel caller may have changed
	// between the two reads.
	if statelessReadRequested() {
		args = append(args, "--stateless")
	} else if uuid := strings.TrimSpace(globalProjectUUID); uuid != "" {
		args = append(args, "--project-uuid", uuid)
	} else if name := strings.TrimSpace(globalProjectName); name != "" {
		args = append(args, "--project-name", name)
	}
	if globalReadOnly {
		args = append(args, "--read-only")
	}
	if cfg := strings.TrimSpace(globalConfig); cfg != "" {
		args = append(args, "--config", cfg)
	}
	return args, true
}

// followUpQuery renders a runnable follow-up command string, pinned to the read
// context. tail is the command and its own flags, e.g.
// []string{"finding", "--id", "5", "--json", "--with-records"}.
//
// Returns "" when the read cannot be reproduced, which the envelope renders as
// an absent `query` field rather than a wrong one.
func followUpQuery(tail ...string) string {
	ctx, ok := readContextArgs()
	if !ok {
		return ""
	}
	parts := make([]string, 0, len(ctx)+len(tail)+1)
	parts = append(parts, "vigolium")
	parts = append(parts, ctx...)
	parts = append(parts, tail...)

	// shellQuoteArg is the resume-command quoter; reusing it means a database
	// path with a space in it is escaped by the same rule in both places.
	quoted := make([]string, 0, len(parts))
	for _, p := range parts {
		quoted = append(quoted, shellQuoteArg(p))
	}
	return strings.Join(quoted, " ")
}
