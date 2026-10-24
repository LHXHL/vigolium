package brotli_request_decoding_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "brotli-request-decoding-exposure"
	ModuleName  = "Brotli Request Decoding Exposure"
	ModuleShort = "Flags servers that decode Brotli request bodies (Content-Encoding: br), the attack surface of CVE-2026-111497 in Node.js, Bun, Envoy/Istio and libbrotli; never sends the crash trigger"
)

var (
	ModuleDesc = `**What it means:** Something on this request path (the app's body parser, middleware, or a proxy such as an Envoy/Istio decompressor) decodes Brotli request bodies, so attacker bytes reach a Brotli decoder. Affected decoders (CVE-2026-111497) have an out-of-bounds write. The decoder's version is not observable remotely, so this is potential exposure only.

**How it's exploited:** On an unpatched decoder, one crafted Brotli body crashes the process and may reach code execution.

**Fix:** Patch the decoder (Node.js 22.23.4/24.22.1/26.12.1, Bun 1.4.4, Envoy 1.37.8+, Istio 1.29.9+, libbrotli 1.0.10/1.1.1/1.2.1), or reject Content-Encoding: br before any decoder runs.`

	ModuleConfirmation = "Reported when the answer follows the decoded content, not the header: Brotli-encoded {} and { are answered like plain {} and { (which differ, on a non-5xx baseline) over two rounds, while the same bytes under an unknown encoding, or under an X-Vigolium-Encoding decoy header, are not, and a random decoy header leaves plain {} unchanged. The crash trigger is never sent"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"brotli", "cve", "light"}
)
