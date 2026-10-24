package node_brotli_decoder_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "node-brotli-decoder-exposure"
	ModuleName  = "Node.js Brotli Request Decoding Exposure"
	ModuleShort = "Detects Express/NestJS apps that decode Brotli request bodies, the attack surface of CVE-2026-111497 (node2shell candidate)"
)

var (
	ModuleDesc = `**What it means:** This Express or NestJS app decodes Brotli-compressed request bodies (Content-Encoding: br), so attacker bytes reach Node.js's Brotli decoder. That decoder has an out-of-bounds write (CVE-2026-111497) in affected Node.js releases. The Node.js version cannot be seen remotely, so this marks exposure, not vulnerability.

**How it's exploited:** On an unpatched runtime, one crafted Brotli request body crashes the process, and on some exact builds reaches remote code execution.

**Fix:** Upgrade Node.js to a release fixed by the October 2026 security advisory (v24.22.1 or later on v24), or disable Brotli inflation in the body parser.`

	ModuleConfirmation = "Reported when the same invalid Brotli body is refused with HTTP 400 (decode failed) under Content-Encoding: br but HTTP 415 (unsupported encoding) under an unknown encoding, showing the body parser accepts br. The crash trigger is never sent"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"express", "nestjs", "nodejs", "cve", "light"}
)
