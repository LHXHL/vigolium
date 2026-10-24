package host_header_injection

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

const evilHost = "evil.vigolium-test.example.com"

// The probed header set and value shapes live in infra.HostHeaderVariants,
// shared with password_reset_poisoning.

// Module implements the Host Header Injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Host Header Injection module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("host_header_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ConfirmsByBodyDifferential opts this module into the executor's body-
// differential safety net: a candidate finding is re-confirmed by replaying the
// injected-Host request and verifying it reproducibly introduces content absent
// from the clean baseline before being reported.
func (m *Module) ConfirmsByBodyDifferential() bool { return true }

// ScanPerRequest tests the request for host header injection.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	var results []*output.ResultEvent

	for _, probe := range infra.HostHeaderVariants {
		value := probe.Value(evilHost)

		modifiedRaw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), probe.Header, value)
		if err != nil {
			continue
		}

		// modifiedRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

		// NoRedirects: the host-injection sink we care about is the IMMEDIATE
		// response (a reflected Location header is the password-reset/cache-poisoning
		// signal). Following the 3xx would consume that Location and chase the
		// injected host off-target.
		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
		if err != nil {
			continue
		}

		// A WAF/CDN challenge, auth gate, or rate-limit page is not the app
		// reflecting the injected host — skip it so its body/headers can't trip
		// the marker (the SSO/Cloudflare-challenge false-positive class).
		if infra.IsBlockedResponse(resp) {
			resp.Close()
			continue
		}

		// Check if the injected host is reflected in the response body or headers AS
		// A URL AUTHORITY — the host component of a generated URL (the redirect
		// Location, an absolute link), which is the actual password-reset / cache-
		// poisoning sink. A bare substring match flagged a recurring false positive:
		// an OAuth login flow behind a CDN echoes the client host into a redirect_uri=
		// query parameter of a 3xx whose authority stays the trusted IdP, so the real
		// destination never changes with or without the spoofed header. Requiring
		// authority position drops that echo while still catching "https://<host>/...".
		body := resp.Body().String()
		headers := resp.Headers().String()

		reflectedInHeader := modkit.HostReflectedAsAuthority(headers, evilHost)
		reflectedInBody := modkit.HostReflectedAsAuthority(body, evilHost)

		var location string
		if reflectedInHeader && resp.Response() != nil {
			location = resp.Response().Header.Get("Location")
		}

		if reflectedInHeader || reflectedInBody {
			// Re-confirm the reflection is genuine and header-attributable, not a
			// coincidental static string, a cached/volatile page, or a catch-all that
			// serves the same body with or without our header: re-send the SAME header
			// with a FRESH random canary host each round and require the canary to
			// reflect every round. A fresh canary is by construction absent from the
			// no-header baseline, so a value that tracks our input proves the app
			// trusts the client host; one that doesn't (an identical body each time)
			// is dropped. Fails OPEN only on a transport error so a transient failure
			// never suppresses a genuine finding.
			if confirmed, cerr := m.confirmHostReflection(ctx, httpClient, probe); cerr == nil && !confirmed {
				resp.Close()
				continue
			}

			// A reflection into a response header / Location is the URL-generation
			// sink that enables password-reset poisoning and cache poisoning — report
			// it Firm. A body-only echo is a weaker signal (the value may never reach a
			// generated link or redirect), so it ships as Tentative.
			findingConfidence := severity.Tentative
			if reflectedInHeader {
				findingConfidence = severity.Firm
			}

			extracted := []string{
				fmt.Sprintf("Header: %s: %s", probe.Header, value),
			}
			if location != "" {
				extracted = append(extracted, fmt.Sprintf("Location: %s", location))
			}

			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(modifiedRaw),
				Response:         resp.FullResponseString(),
				ExtractedResults: extracted,
				Info: output.Info{
					Name:        fmt.Sprintf("Host Header Injection: %s", probe.Header),
					Description: probe.Desc,
					Confidence:  findingConfidence,
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}

// confirmHostReflection re-sends the probe's header with a FRESH random canary
// host each round (rendered through the variant's value template) and requires the canary to reflect
// in the response every round. Because each canary is unique and absent from the
// no-header baseline, a reflection that reproduces proves the app echoes the
// client-supplied host; a fixed string, a cached page, or a catch-all that serves
// an identical body regardless of the header does not track the canary and is
// dropped. A blocked/challenge page is never counted as a reflection. Returns
// (confirmed, err); err != nil signals a transport failure so the caller can fail
// open rather than suppress a genuine finding.
func (m *Module) confirmHostReflection(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	probe infra.HostHeaderVariant,
) (bool, error) {
	return modkit.ConfirmReflection(2, func(canary string) (bool, error) {
		canaryHost := canary + ".vigolium-hhi.example"
		// Probes with a structured value (e.g. Forwarded: host=<h>) keep their
		// shape with the fresh canary in place of the sentinel host.
		value := probe.Value(canaryHost)
		raw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), probe.Header, value)
		if err != nil {
			return false, err
		}
		// raw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
		req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
		resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true, NoRedirects: true})
		if err != nil {
			return false, err
		}
		defer resp.Close()
		if resp.Response() == nil {
			return false, fmt.Errorf("host-header confirmation: nil response")
		}
		if infra.IsBlockedResponse(resp) {
			return false, nil // a WAF/challenge page is not a host reflection
		}
		// Require the canary in URL-authority position (matching the primary probe),
		// so a redirect_uri=/next= query-parameter echo of the canary does not
		// "confirm" a reflection that the authority-gated detection already rejects.
		return modkit.HostReflectedAsAuthority(resp.FullResponseString(), canaryHost), nil
	})
}
