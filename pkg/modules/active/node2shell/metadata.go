package node2shell

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "node2shell"
	ModuleName  = "node2shell Brotli Decoder Version Probe"
	ModuleShort = "Flags request paths whose Brotli decoder predates the CVE-2026-111497 fix, using a 22 MiB stream only an affected decoder accepts; ~22 MiB of upload against a patched host, ~66 MiB against a candidate, once per origin"
)

var (
	ModuleDesc = `**What it means:** A Brotli stream that only a decoder without the CVE-2026-111497 fix can decode was decoded on this request path. The route answered it exactly as it answers a plain {} body, while a size-matched malformed twin was refused. That points at an unpatched Brotli decoder (node2shell).

**How it's exploited:** An unauthenticated attacker sends a crafted Brotli request body to any route behind that decoder, corrupting memory and, on affected builds, reaching remote code execution.

**Fix:** Patch the decoder (Node.js 22.23.4/24.22.1/26.12.1, Bun 1.4.4, Envoy 1.37.8+, Istio 1.29.9+, libbrotli 1.0.10/1.1.1/1.2.1), or reject Content-Encoding: br before any decoder runs.`

	ModuleConfirmation = "Reported when a ten-request decode differential first proves the path decodes plain Brotli request bodies and distinguishes three response classes ({}, malformed JSON, and a stream the decoder refuses); then the 23,068,764-byte probe is answered like plain {} over two rounds with all three classes re-proven in between, its 23,068,775-byte twin — malformed for every decoder — is answered like a refused stream rather than like {} (so the divergence follows the decode, not the body size), the route still answers the tiny valid control afterwards, and the endpoint is not volatile. A patched decoder refuses the probe on the first round and nothing is reported. The decoder's build is not observable remotely, so the verdict stays a lead"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Tentative
	// "intrusive" drops the module at --intensity quick and keeps it in from
	// balanced up, matching php2shell, the other multi-MiB CVE probe. Each
	// origin that passes the gate costs ~44 MiB of upload, but the gate itself
	// is ten sub-32-byte requests and closes on everything that does not decode
	// Brotli request bodies, so the spend is rare rather than per-host.
	//
	// Not risk:high — the probe decodes to 66 bytes of valid JSON and executes
	// nothing, so it is gentler on availability than php2shell, which carries
	// the same tier while deliberately killing workers. Add risk:high if the
	// upload should need --intensity deep or --allow-risky-payloads.
	ModuleTags = []string{"brotli", "cve", "rce", "intrusive"}
)
