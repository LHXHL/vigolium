// Package iisgate provides an active, cached confirmation that a host genuinely
// runs IIS/ASP.NET before the heavier IIS modules probe it. Passive header or
// tech-registry signals (Server: Microsoft-IIS, X-AspNet-Version, ASP.NET
// cookies) can be spoofed by an unrelated proxy, so the IIS modules combine
// those with the behavioral check here: only a real ASP.NET pipeline strips a
// cookieless (S(token)) segment from the path and still resolves the request.
package iisgate

import (
	"strings"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

const cacheSize = 4096

var (
	cacheOnce sync.Once
	cache     *lru.Cache[string, bool]
)

func getCache() *lru.Cache[string, bool] {
	cacheOnce.Do(func() {
		c, _ := lru.New[string, bool](cacheSize)
		cache = c
	})
	return cache
}

// ConfirmIISBehavior actively verifies that host exhibits ASP.NET/IIS cookieless
// path normalization and caches the verdict per host (so it runs at most once
// per host across all IIS modules). It anchors on the site root, then confirms
// that wrapping it in a (S(token)) cookieless segment resolves to the SAME
// resource (the token was stripped) while a random path does NOT (ruling out a
// catch-all that echoes one page for everything). A spoofed Server header cannot
// fake this, so a positive result means the target really is running ASP.NET.
func ConfirmIISBehavior(host string, ctx *httpmsg.HttpRequestResponse, client *http.Requester) bool {
	if ctx == nil || ctx.Request() == nil || client == nil {
		return false
	}
	c := getCache()
	if v, ok := c.Get(host); ok {
		return v
	}
	v := probeIIS(ctx, client)
	c.Add(host, v)
	return v
}

// ResetCache clears the per-host verdict cache (test helper).
func ResetCache() {
	getCache().Purge()
}

// RespLooksIIS reports whether a response's headers advertise IIS/ASP.NET.
func RespLooksIIS(resp *httpmsg.HttpResponse) bool {
	if resp == nil {
		return false
	}
	if strings.Contains(strings.ToLower(resp.Header("Server")), "microsoft-iis") {
		return true
	}
	if resp.HasHeader("X-AspNet-Version") || resp.HasHeader("X-AspNetMvc-Version") {
		return true
	}
	return strings.Contains(strings.ToLower(resp.Header("X-Powered-By")), "asp.net")
}

// LooksLikeIIS is the passive gate: this record's headers, or the shared per-host
// tech registry (populated by the passive aspnet_fingerprint module), indicate
// IIS/ASP.NET.
func LooksLikeIIS(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext, host string) bool {
	if ctx != nil && ctx.Response() != nil && RespLooksIIS(ctx.Response()) {
		return true
	}
	return scanCtx.HasAnyTech(host, []string{"iis", "aspnet"})
}

// IsIIS is the full gate for the heavier IIS modules: passive detection
// (LooksLikeIIS) AND active behavioral confirmation (ConfirmIISBehavior, cached
// per host). A spoofed Server header alone therefore never passes.
func IsIIS(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext, host string, client *http.Requester) bool {
	return LooksLikeIIS(ctx, scanCtx, host) && ConfirmIISBehavior(host, ctx, client)
}

type resp struct {
	status int
	body   string
	ok     bool
}

func fetch(ctx *httpmsg.HttpRequestResponse, client *http.Requester, path string) resp {
	raw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return resp{}
	}
	raw, err = httpmsg.SetPath(raw, path)
	if err != nil {
		return resp{}
	}
	st, body, ok := modkit.ExecuteRaw(client, ctx.Service(), raw, http.Options{NoRedirects: true, NoClustering: true})
	return resp{status: st, body: body, ok: ok}
}

// anchorable reports whether a status can serve as a stable anchor resource.
func anchorable(status int) bool {
	switch status {
	case 200, 301, 302, 401, 403:
		return true
	}
	return false
}

func probeIIS(ctx *httpmsg.HttpRequestResponse, client *http.Requester) bool {
	base := fetch(ctx, client, "/")
	if !base.ok || !anchorable(base.status) {
		return false
	}
	token := "(S(" + strings.ToLower(modkit.FreshCanary()) + "))"
	tok := fetch(ctx, client, "/"+token+"/")
	rnd := fetch(ctx, client, "/"+modkit.FreshCanary()+"-vigolium404/")
	return decideIIS(base, tok, rnd)
}

// decideIIS is the pure verdict function (extracted for testability): the
// cookieless-wrapped anchor must match the anchor and a random path must differ.
func decideIIS(base, tok, rnd resp) bool {
	if !base.ok || !tok.ok || !rnd.ok {
		return false
	}
	sameAsBase := tok.status == base.status && modkit.BodiesSimilar(tok.body, base.body)
	distinctRandom := rnd.status != base.status || !modkit.BodiesSimilar(rnd.body, base.body)
	return sameAsBase && distinctRandom
}
