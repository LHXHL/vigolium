package parammine

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// volatileHeaders are response headers whose presence varies between identical
// requests (or follows the body size), so they never count toward the header
// signal.
var volatileHeaders = map[string]bool{
	"date": true, "age": true, "expires": true, "last-modified": true, "etag": true,
	"content-length": true, "transfer-encoding": true, "connection": true, "keep-alive": true,
	"server-timing": true, "x-request-id": true, "x-runtime": true, "x-response-time": true,
	"cf-ray": true, "x-amz-cf-id": true, "x-amz-request-id": true, "x-amzn-requestid": true,
	"x-amzn-trace-id": true, "x-cache": true, "x-cache-hits": true, "x-served-by": true,
	"x-timer": true, "via": true, "report-to": true, "nel": true,
}

// profile is the endpoint's baseline behaviour under an unknown parameter.
type profile struct {
	status int
	// headerSet is the stable header-name set; headersUsable is false when the
	// two baselines disagreed on it, which turns the header signal off.
	headerSet     string
	headersUsable bool
	// reflectUsable is false when a baseline echoed its own random value: the
	// endpoint reflects any parameter, so a reflection names nothing.
	reflectUsable bool

	bodies  [2]string // raw baseline bodies, cleaned per comparison
	reflect [2][]pair // what each baseline sent, stripped from both sides
}

// newProfile builds the profile from two baselines. stable is false when they
// disagree on status or body: the endpoint answers the same request two ways,
// so no difference can be pinned on a parameter.
func newProfile(a, b *probe) (*profile, bool) {
	p := &profile{
		status:        a.resp.StatusCode(),
		bodies:        [2]string{a.resp.BodyToString(), b.resp.BodyToString()},
		reflect:       [2][]pair{a.pairs, b.pairs},
		reflectUsable: len(a.reflected) == 0 && len(b.reflected) == 0,
	}
	if a.resp.StatusCode() != b.resp.StatusCode() {
		return nil, false
	}
	ha, hb := headerSet(a.resp), headerSet(b.resp)
	p.headerSet, p.headersUsable = ha, ha == hb

	strip := append(append([]pair(nil), a.pairs...), b.pairs...)
	sa := signature(p.status, p.bodies[0], strip)
	sb := signature(p.status, p.bodies[1], strip)
	if modkit.IsDifferent(sa, sb) || !modkit.RatioSimilar(sa, sb) {
		return nil, false
	}
	return p, true
}

// differs compares a probe against the baseline and names the first signal
// that sets it apart. Reflection is handled by the caller; this covers status,
// header set and body. The body comparison strips the probe's and the
// baselines' parameters from both sides, so a page that echoes the query
// string is compared on what the parameters did, not on the echo.
func (p *profile) differs(pr *probe) (Signal, string, bool) {
	status := pr.resp.StatusCode()
	if status != p.status {
		return SignalStatus, fmt.Sprintf("status %d -> %d", p.status, status), true
	}
	if p.headersUsable {
		if hs := headerSet(pr.resp); hs != p.headerSet {
			return SignalHeader, "response header set changed: " + headerDelta(p.headerSet, hs), true
		}
	}

	strip := make([]pair, 0, len(pr.pairs)+len(p.reflect[0])+len(p.reflect[1]))
	strip = append(strip, pr.pairs...)
	strip = append(strip, p.reflect[0]...)
	strip = append(strip, p.reflect[1]...)
	probeBody := pr.resp.BodyToString()
	ps := signature(status, probeBody, strip)
	// Different from BOTH baselines: a page that alternates between two
	// renderings matches one of them.
	for i := range p.bodies {
		bs := signature(p.status, p.bodies[i], strip)
		if !modkit.IsDifferent(bs, ps) && modkit.RatioSimilar(bs, ps) {
			return "", "", false
		}
	}
	bs := signature(p.status, p.bodies[0], strip)
	if modkit.IsDifferent(bs, ps) || modkit.HasSubstantialBodyDifference(bs, ps) {
		return SignalLength, fmt.Sprintf("body length %d -> %d", bs.BodyLength, ps.BodyLength), true
	}
	return SignalBody, fmt.Sprintf("body content changed (similarity %.2f)", modkit.QuickRatio(bs, ps)), true
}

// signature is the comparison signature of a body with every sent parameter
// (canary values, and names long enough to be distinctive) and the query
// separators removed. The same strip list is applied to both sides of a
// comparison, so removing common words cannot itself create a difference.
func signature(status int, body string, strip []pair) modkit.ResponseSignature {
	return modkit.NewResponseSignature(status, cleanBody(body, strip), "")
}

func cleanBody(body string, strip []pair) string {
	if body == "" {
		return body
	}
	olds := make([]string, 0, 2*len(strip)+6)
	for _, p := range strip {
		if len(p.value) >= 3 {
			olds = append(olds, p.value, "")
		}
	}
	for _, p := range strip {
		if len(p.name) >= 3 {
			olds = append(olds, p.name, "")
		}
	}
	// What is left of an echoed query string once names and values are gone.
	olds = append(olds, "&amp;", "", "&", "", "=", "")
	return strings.NewReplacer(olds...).Replace(body)
}

// headerSet renders the response's stable header names, sorted and joined.
func headerSet(resp *httpmsg.HttpResponse) string {
	seen := make(map[string]bool)
	for _, h := range resp.Headers() {
		n := strings.ToLower(strings.TrimSpace(h.Name))
		if n == "" || volatileHeaders[n] {
			continue
		}
		seen[n] = true
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// headerDelta describes how two header sets differ, e.g. "+set-cookie -vary".
func headerDelta(base, got string) string {
	in := func(set string) map[string]bool {
		m := make(map[string]bool)
		for _, n := range strings.Split(set, ",") {
			if n != "" {
				m[n] = true
			}
		}
		return m
	}
	b, g := in(base), in(got)
	var parts []string
	for n := range g {
		if !b[n] {
			parts = append(parts, "+"+n)
		}
	}
	for n := range b {
		if !g[n] {
			parts = append(parts, "-"+n)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

// reflectedNames reports which pairs' canary values appear in the response,
// headers included (a redirect that carries the value is an echo too).
func reflectedNames(resp *httpmsg.HttpResponse, pairs []pair) map[string]bool {
	raw := resp.Raw()
	var out map[string]bool
	for _, p := range pairs {
		if len(p.value) < canaryLen {
			continue
		}
		if bytes.Contains(raw, []byte(p.value)) {
			if out == nil {
				out = make(map[string]bool)
			}
			out[p.name] = true
		}
	}
	return out
}
