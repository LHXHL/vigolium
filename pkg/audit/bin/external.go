//go:build audit_external

package bin

// An `audit_external` build embeds no helper. It downloads the pinned
// vigolium-audit on first use from VIGOLIUM_AUDIT_BASE_URL (download.go),
// verifies it against the generated pins_gen.go table and installs it into the
// same sha-keyed cache an embedded build extracts to. Default builds keep
// embedding: no CDN hosts the helpers yet.
var helperSource source = downloadSource{}
