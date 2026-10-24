package node_brotli_decoder_exposure

import (
	"fmt"
	"mime"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// techTags are the stacks whose default body parser (body-parser 2.x) inflates
// Brotli request bodies. A host must carry one of them; "nodejs" alone is not
// enough, because the Next/Nuxt fingerprints publish it and their route
// handlers do not run body-parser.
var techTags = []string{"express", "nestjs"}

const (
	// probePath is a route no app defines: an app-wide parser (NestJS, a global
	// app.use(express.json())) runs before routing, so the probe is decoded and
	// refused without reaching any handler.
	probePath = "/vigolium-brotli-decoder-check"
	// unknownEncoding is the control encoding. body-parser refuses an encoding it
	// does not know with 415 before reading the body.
	unknownEncoding = "x-vigolium"
	// maxRoutesPerOrigin caps how many recorded routes are probed per origin when
	// the app-wide probe shows nothing (the parser may be mounted per route).
	maxRoutesPerOrigin = 3
)

// probeBody is invalid as Brotli (Node.js rejects it with
// ERR__ERROR_FORMAT_PADDING_2), so decoding fails before any route handler
// runs. It is a few bytes: nowhere near the CVE-2026-111497 trigger.
var probeBody = []byte("vigolium")

// Module implements the Brotli request-decoding exposure check.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Node.js Brotli decoding exposure module.
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
		ds: dedup.LazyDiskSet("node_brotli_decoder_exposure"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// RequiredTechs implements modules.TechAware. The executor's gate fails OPEN on
// a host with no detected stack (and is off at --intensity deep), so
// ScanPerRequest re-checks and fails CLOSED.
func (m *Module) RequiredTechs() []string { return techTags }

// IncludesBaseCanProcess returns false because this module uses a custom CanProcess.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess accepts any record with a request; probes are rebuilt from it.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil && ctx.Service() != nil
}

// ScanPerRequest probes the origin's app-wide parser once, then up to
// maxRoutesPerOrigin recorded body-carrying routes, until one shows decoding.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	u, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	if !hasNodeTech(scanCtx, modkit.RegistryHostKey(ctx)) {
		return nil, nil
	}
	origin := u.Scheme + "://" + u.Host
	ds := m.ds.Get(scanCtx.DedupMgr())
	if ds != nil && ds.Contains("found|"+origin) {
		return nil, nil
	}

	var r *output.ResultEvent
	if ds == nil || !ds.IsSeen("global|"+origin) {
		r = check(ctx, httpClient, u.Host, origin, "POST", probePath, "application/json", "app-wide body parser")
	}
	if r == nil {
		method := ctx.Request().Method()
		contentType := ctx.Request().Header("Content-Type")
		if !carriesParsedBody(method, contentType) {
			return nil, nil
		}
		path := ctx.Request().Path()
		if ds != nil {
			if ds.IsSeen("route|" + origin + "|" + method + " " + path) {
				return nil, nil
			}
			if _, ok := ds.IncrementAndCheck("routes|"+origin, maxRoutesPerOrigin); !ok {
				return nil, nil
			}
		}
		r = check(ctx, httpClient, u.Host, origin, method, path, contentType, "route body parser")
	}
	if r == nil {
		return nil, nil
	}
	if ds != nil {
		ds.IsSeen("found|" + origin)
	}
	return []*output.ResultEvent{r}, nil
}

func hasNodeTech(scanCtx *modkit.ScanContext, host string) bool {
	for _, tag := range techTags {
		if scanCtx.HasTech(host, tag) {
			return true
		}
	}
	return false
}

// carriesParsedBody reports whether a recorded request is one a body parser
// handles: a body-carrying method with a JSON, form or text content type.
func carriesParsedBody(method, contentType string) bool {
	switch method {
	case "POST", "PUT", "PATCH":
	default:
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json") ||
		mediaType == "application/x-www-form-urlencoded" || strings.HasPrefix(mediaType, "text/")
}

// check sends the invalid Brotli body under Content-Encoding: br and under an
// unknown encoding. A 400 for br against a 415 for the unknown encoding means
// the parser accepted br and its decoder failed on the bytes.
func check(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, host, origin, method, path, contentType, lane string) *output.ResultEvent {
	br, ok := send(ctx, httpClient, method, path, contentType, "br")
	if !ok || br.status != 400 {
		return nil
	}
	unknown, ok := send(ctx, httpClient, method, path, contentType, unknownEncoding)
	if !ok || unknown.status != 415 {
		return nil
	}
	target := origin + path
	return &output.ResultEvent{
		ModuleID: ModuleID,
		Host:     host,
		URL:      target,
		Matched:  target,
		Request:  br.request,
		Response: br.response,
		ExtractedResults: []string{
			"Lane: " + lane,
			fmt.Sprintf("Content-Encoding: br -> HTTP %d (Brotli decode failed)", br.status),
			fmt.Sprintf("Content-Encoding: %s -> HTTP %d (encoding refused)", unknownEncoding, unknown.status),
			"Node.js version not observable: check it against the CVE-2026-111497 advisory",
		},
		AdditionalEvidence: []string{
			"Unknown-encoding control request:\n" + unknown.request + "\n\nControl response:\n" + unknown.response,
		},
		Info: output.Info{
			Name:        "Brotli request-body decoding reachable (CVE-2026-111497 / node2shell candidate)",
			Description: fmt.Sprintf("The %s at %s decodes Content-Encoding: br request bodies, reaching the Node.js Brotli decoder affected by CVE-2026-111497.", lane, path),
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        []string{"nodejs", "express", "brotli", "cve-2026-111497", "node2shell"},
			Reference: []string{
				"https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
				"https://github.com/google/brotli/commit/0ed4268a4401abcb44720963",
				"https://expressjs.com/en/resources/middleware/body-parser.html",
			},
		},
		Metadata: map[string]any{
			"lane":   lane,
			"method": method,
			"path":   path,
		},
	}
}

type exchange struct {
	status   int
	request  string
	response string
}

// send replays the record as method+path with the probe body and the given
// Content-Encoding. Redirects are not followed and the response cache is
// bypassed (the two probes differ only in a header).
func send(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, method, path, contentType, encoding string) (exchange, bool) {
	raw, err := buildRequest(ctx.Request().Raw(), method, path, contentType, encoding)
	if err != nil {
		return exchange{}, false
	}
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return exchange{}, false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return exchange{}, false
	}
	return exchange{
		status:   resp.Response().StatusCode,
		request:  string(raw),
		response: modkit.Truncate(resp.FullResponseString(), 2048),
	}, true
}

func buildRequest(raw []byte, method, path, contentType, encoding string) ([]byte, error) {
	raw, err := httpmsg.SetMethod(raw, method)
	if err != nil {
		return nil, err
	}
	if raw, err = httpmsg.SetPath(raw, path); err != nil {
		return nil, err
	}
	if raw, err = httpmsg.RemoveHeader(raw, "Transfer-Encoding"); err != nil {
		return nil, err
	}
	if raw, err = httpmsg.AddOrReplaceHeader(raw, "Content-Type", contentType); err != nil {
		return nil, err
	}
	if raw, err = httpmsg.AddOrReplaceHeader(raw, "Content-Encoding", encoding); err != nil {
		return nil, err
	}
	return httpmsg.SetBody(raw, probeBody)
}
