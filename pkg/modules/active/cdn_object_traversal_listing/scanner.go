package cdn_object_traversal_listing

import (
	"fmt"
	"strings"

	urlutil "github.com/projectdiscovery/utils/url"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/storagesig"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	// probeBudget hard-caps requests per (host, bucket) so an unconfirmable
	// candidate cannot blow up the request count.
	probeBudget = 120
	// maxResponseStore caps how much of a leaked listing we keep as evidence.
	maxResponseStore = 4096
)

type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

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
		ds: dedup.LazyDiskSet("cdn_object_traversal_listing"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess gates on behavioral object-storage signals (the /obj/ path shape
// or storage response headers), NOT a hostname allowlist — so it catches vanity
// CDN domains fronting GCS/TOS. It deliberately runs on media/asset URLs.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	switch ctx.Request().Method() {
	case "OPTIONS", "CONNECT", "TRACE":
		return false
	}
	urlx, err := ctx.URL()
	if err != nil {
		return false
	}
	if storagesig.LooksLikeStorageObjectPath(urlx.Path) {
		return true
	}
	if ctx.HasResponse() && storagesig.ResponseHasStorageSignal(ctx.Response()) {
		return true
	}
	return false
}

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	if ctx == nil || ctx.Request() == nil {
		return nil, nil
	}
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	switch ctx.Request().Method() {
	case "OPTIONS", "CONNECT", "TRACE":
		return nil, nil
	}

	objPath := strings.TrimRight(urlx.Path, "/")
	if objPath == "" || objPath == "/" {
		return nil, nil
	}

	bucketKey := urlx.Hostname() + "|" + storagesig.BucketPrefix(urlx.Path)
	ds := m.ds.Get(scanCtx.DedupMgr())
	if ds != nil && ds.Contains(bucketKey) {
		return nil, nil // another object under this bucket already tested
	}

	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	rawGET := ctx.Request().Raw()
	if ctx.Request().Method() != "GET" {
		if swapped, serr := httpmsg.SetMethod(rawGET, "GET"); serr == nil {
			rawGET = swapped
		}
	}

	budget := probeBudget

	// Stage 0: stable, clean baseline. The active module always issues its own
	// GET — the triggering request may be a metadata HEAD with an empty body.
	base := m.fetch(httpClient, service, rawGET, objPath, false, &budget)
	if !base.ok {
		return nil, nil
	}
	if _, isList := storagesig.StrongListing(base.body); isList {
		return nil, nil // already a public listing -> not a traversal finding
	}
	base2 := m.fetch(httpClient, service, rawGET, objPath, true, &budget)
	if !base2.ok {
		return nil, nil
	}
	if _, isList := storagesig.StrongListing(base2.body); isList {
		return nil, nil // racy/unstable baseline -> refuse to test (avoid FP)
	}

	// Commit to testing this bucket exactly once.
	if ds != nil && ds.IsSeen(bucketKey) {
		return nil, nil
	}

	// Wildcard guard: a host that 200s every path is not a traversal.
	wildcard, _ := scanCtx.WildcardProbe(ctx, httpClient)

	// Catch-all guard: a non-collapsing matrix-param suffix must NOT list.
	for _, c := range controlTokens {
		cb := m.fetch(httpClient, service, rawGET, joinProbe(objPath, c), false, &budget)
		if cb.ok {
			if _, isList := storagesig.StrongListing(cb.body); isList {
				return nil, nil // blanket listing -> reject candidate
			}
		}
	}

	leaf := storagesig.ObjectLeaf(urlx.Path)

	for _, pass := range []int{1, 2} {
		promising := false
		for _, tk := range tierTokens(pass) {
			if budget <= 0 {
				return nil, nil
			}
			probePath := joinProbe(objPath, tk.tok)
			pb := m.fetch(httpClient, service, rawGET, probePath, false, &budget)
			if !pb.ok || matchesWildcard(wildcard, pb.status, pb.body) {
				continue
			}
			prov, isList := storagesig.StrongListing(pb.body)
			if !isList {
				if pb.status >= 200 && pb.status < 400 && !strings.EqualFold(pb.body, base.body) {
					promising = true // distinct off-object body -> unlock tier 2
				}
				continue
			}
			// Reproduce on a cache-busting re-fetch.
			rb := m.fetch(httpClient, service, rawGET, probePath, true, &budget)
			if !rb.ok || matchesWildcard(wildcard, rb.status, rb.body) {
				continue
			}
			if _, isList2 := storagesig.StrongListing(rb.body); !isList2 {
				continue
			}
			// Clean-canonical control: the token collapses objPath to an ancestor
			// directory. If that ancestor is ALREADY publicly listable via a
			// plain, un-obfuscated request (no traversal token), the bucket simply
			// has anonymous ListObjects enabled on that prefix — the trailing
			// segment escaped no access-control boundary and this is not a
			// traversal finding (it would be cloud-storage-listing's domain).
			if cleanPath := collapsedParentPath(objPath, tk.tok); cleanPath != "" {
				cp := m.fetch(httpClient, service, rawGET, cleanPath, true, &budget)
				if cp.ok {
					if _, isList := storagesig.StrongListing(cp.body); isList {
						return nil, nil
					}
				}
			}
			return []*output.ResultEvent{m.buildFinding(urlx, rawGET, probePath, pb.body, prov, tk.tok, leaf)}, nil
		}
		if pass == 1 && !promising {
			return nil, nil // tier 1 reached nothing distinct -> don't unfurl tier 2
		}
	}
	return nil, nil
}

type probeResult struct {
	status int
	body   string
	ok     bool
}

func (m *Module) fetch(
	httpClient *http.Requester,
	service *httpmsg.Service,
	rawGET []byte,
	path string,
	noClustering bool,
	budget *int,
) probeResult {
	if *budget <= 0 {
		return probeResult{}
	}
	*budget--

	raw, err := httpmsg.SetPath(rawGET, path)
	if err != nil {
		return probeResult{}
	}
	raw, _ = httpmsg.ClearQueryString(raw)

	// SetPath/ClearQueryString produce well-formed raw, so wrap directly
	// instead of re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(raw, service)

	resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: noClustering})
	if err != nil {
		return probeResult{}
	}
	defer resp.Close()
	if resp.Response() == nil {
		return probeResult{}
	}
	return probeResult{status: resp.Response().StatusCode, body: resp.Body().String(), ok: true}
}

func (m *Module) buildFinding(
	urlx *urlutil.URL,
	rawGET []byte,
	probePath, body, provider, tok, leaf string,
) *output.ResultEvent {
	keys := storagesig.ListingKeys(body, 20)
	conf := severity.Firm
	leafMatch := storagesig.ListingContainsLeaf(keys, leaf)
	if leafMatch {
		conf = severity.Certain
	}

	rawReq, err := httpmsg.SetPath(rawGET, probePath)
	if err == nil {
		rawReq, _ = httpmsg.ClearQueryString(rawReq)
	} else {
		rawReq = rawGET
	}

	evidence := []string{
		"Provider: " + provider,
		"Payload (trailing segment): /" + tok,
		fmt.Sprintf("Listed object keys: %d", len(keys)),
	}
	if leafMatch {
		evidence = append(evidence, "Requested object leaf present in listing (parent directory confirmed): "+leaf)
	}
	if len(keys) > 0 {
		sample := keys
		if len(sample) > 5 {
			sample = sample[:5]
		}
		evidence = append(evidence, "Sample keys: "+strings.Join(sample, ", "))
	}

	desc := fmt.Sprintf(
		"Object-storage path traversal: appending %q to object path %q turned a GetObject into a %s bucket listing (%d object keys), absent from the object's own stable baseline response. "+
			"The CDN/gateway forwarded the non-canonical trailing segment unchanged while the storage backend collapsed it to the parent directory and fell back to ListObjects. "+
			"A non-collapsing control suffix did not list, attributing the listing specifically to the parent collapse, and the listing reproduced on a cache-busting re-fetch.",
		"/"+tok, urlx.Path, provider, len(keys),
	)

	matchedURL := urlx.Scheme + "://" + urlx.Host + probePath
	return &output.ResultEvent{
		ModuleID: m.ID(),
		URL:      matchedURL,
		Host:     urlx.Host,
		// Full absolute URL so the console/grouping (MatchedURL prefers Matched)
		// shows the target host like every other active module, not a bare path.
		Matched:          matchedURL,
		Request:          string(rawReq),
		Response:         modkit.TruncateNoEllipsis(body, maxResponseStore),
		FuzzingParameter: "url-path",
		ExtractedResults: evidence,
		Info: output.Info{
			Name:        "CDN Object-Storage Traversal Listing",
			Description: desc,
			Severity:    severity.High,
			Confidence:  conf,
			Tags:        ModuleTags,
			Reference:   []string{"https://hackerone.com/reports/3523931"},
		},
	}
}

// collapseDepth counts the parent-collapse units in a traversal token — each
// ".." (literal, %2e%2e, or double-encoded %252e%252e) pops one path segment.
// The three forms are textually disjoint (no encoded form is a substring of
// another), so they can be counted independently. Defaults to 1 so a malformed
// token still tests the immediate parent.
func collapseDepth(tok string) int {
	d := strings.Count(tok, "..") +
		strings.Count(tok, "%2e%2e") +
		strings.Count(tok, "%252e%252e")
	if d < 1 {
		return 1
	}
	return d
}

// collapsedParentPath returns the clean ancestor directory a parent-collapse
// token resolves objPath to — stripping one trailing segment per ".." unit and
// re-appending a trailing slash. This is the path a plain, un-obfuscated request
// would address (the clean-canonical control). Returns "" when the token would
// climb past the path root (no clean ancestor to test).
func collapsedParentPath(objPath, tok string) string {
	depth := collapseDepth(tok)
	segs := strings.Split(strings.Trim(objPath, "/"), "/")
	if depth >= len(segs) {
		return ""
	}
	return "/" + strings.Join(segs[:len(segs)-depth], "/") + "/"
}

func matchesWildcard(wildcard *modkit.WildcardEntry, status int, body string) bool {
	return wildcard.IsWildcard() && wildcard.MatchesBody(status, []byte(body))
}
