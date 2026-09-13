package cli

import (
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// The -j envelope names its row array `items`. Before the envelope existed each
// command named it something else — `records` on traffic, `findings` on finding,
// `scans`/`rows` on db — and those old names were kept as aliases so parsers
// written against them would keep working.
//
// The alias is not free, and the cost is not the one the original comment
// assumed. It is rendered by marshaling Items a SECOND time and appending the
// bytes, so the rows appear twice ON THE WIRE: a 20-record compact
// `traffic -j` measures 19,983 bytes whole against 7,884 bytes of `items`. For
// the consumer this contract was designed for — an LLM that pays per token for
// every byte it reads back — the deprecated half of a duplicated payload is the
// single largest avoidable cost in the read path, and it is paid on every call.
//
// So the default is now off: `items` only. The alias survives one flag behind
// it, for a caller that cannot be migrated in the same change, and the flag
// exists to be deleted. This is the documented migration window, not a
// permanent second contract — `items` has been canonical and documented since
// schema_version 1, and the aliases were marked "to be removed, never added to"
// on the day they were written.
//
// It is not a schema_version bump: the envelope is gaining no field, changing no
// type, and renaming nothing. A consumer reading `items` — which is every
// consumer written against the documented contract — sees byte-identical output.

// globalJSONLegacyKeys backs the persistent --json-legacy-keys flag.
var globalJSONLegacyKeys bool

// jsonLegacyKeysEnv lets a wrapper script that cannot edit its argv (a CI job, a
// vendored harness) re-enable the aliases for the whole process.
const jsonLegacyKeysEnv = "VIGOLIUM_JSON_LEGACY_KEYS"

// registerJSONLegacyKeysFlag adds the persistent --json-legacy-keys flag.
//
// Hidden on purpose: a deprecated compatibility switch listed in `--help` reads
// as a supported choice, and the choice it offers is "pay double for a field you
// should stop reading". It stays discoverable where it matters — in this file,
// in the error a migrating caller searches for, and in the docs.
// The env var is resolved ONCE, as the flag's default, rather than consulted
// from the render path. That makes the precedence the same rule every other
// env-backed flag in the tree uses (an explicit --json-legacy-keys=false still
// wins, and Changed() stays meaningful), and keeps MarshalJSON off the process
// environment.
func registerJSONLegacyKeysFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(&globalJSONLegacyKeys, "json-legacy-keys", envBool(jsonLegacyKeysEnv),
		"DEPRECATED: also emit the pre-envelope row alias (records/findings/scans/rows) beside `items`, doubling the payload. For callers still migrating to `items`; will be removed.")
	_ = cmd.PersistentFlags().MarkHidden("json-legacy-keys")
}

// jsonLegacyKeysEnabled reports whether the envelope should render the alias.
func jsonLegacyKeysEnabled() bool { return globalJSONLegacyKeys }

// envBool reads a boolean environment variable, treating unset and unparseable
// alike as false. An unparseable value is not an error: this backs a
// compatibility shim, and failing a read command over the spelling of a
// deprecation switch is a worse outcome than emitting the modern shape.
func envBool(name string) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return false
	}
	on, err := strconv.ParseBool(raw)
	return err == nil && on
}
