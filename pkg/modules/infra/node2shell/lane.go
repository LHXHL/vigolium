package node2shell

import (
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// ProbePath is a route no app defines. An app-wide parser (NestJS, a global
// app.use(express.json())) or a decoding proxy runs before routing, so a probe
// sent here is decoded without reaching any handler — which separates a parser
// mounted on the whole app from one mounted on a single route.
const ProbePath = "/vigolium-brotli-decoder-check"

// MaxRoutesPerOrigin caps how many recorded routes the differential is run
// against per origin once the unrouted path has shown nothing.
const MaxRoutesPerOrigin = 3

// Lane names where a decoder was found, for the reader and for Metadata.
const (
	LaneHost  = "app-wide parser or proxy"
	LaneRoute = "route body parser"
)

// OriginOf returns the record's normalized origin, the key both modules budget
// by. Normalization matters here precisely because it IS the budget key: an
// explicit :443 and an uppercase host must not each buy their own 22 MiB probe
// of the same server.
func OriginOf(ctx *httpmsg.HttpRequestResponse) string {
	u, err := ctx.URL()
	if err != nil {
		return ""
	}
	return httpmsg.OriginFromURL(u.String())
}

// CarriesJSONBody reports whether a recorded request is one the differential
// can probe: a POST or PATCH with a JSON body. PUT is skipped because PUT {}
// can replace a resource; the oracle needs a malformed JSON body, so form and
// text bodies are not probed.
func CarriesJSONBody(method, contentType string) bool {
	return (method == "POST" || method == "PATCH") &&
		modkit.ClassifyContentType(contentType) == modkit.ContentClassJSON
}

// Budget rations the differential across an origin: it runs on the unrouted
// path once, then on at most MaxRoutesPerOrigin recorded routes, and stops
// entirely once the origin has produced its answer.
//
// It lives here rather than in either module because the two modules have to
// agree on WHERE they look for a decoder — the cheap exposure record and the
// expensive version record describing different paths of the same origin is
// the failure this shared package exists to prevent. Leaving the policy
// copy-maintained in both scanners made that agreement a matter of keeping two
// identical blocks in sync. Each module still owns its own DiskSet, so the keys
// below never collide between them.
type Budget struct {
	ds *dedup.DiskSet
}

// NewBudget wraps a module's DiskSet. A nil set (stateless scans, bare-context
// tests) yields a Budget that permits everything.
func NewBudget(ds *dedup.DiskSet) Budget { return Budget{ds: ds} }

// Settled reports whether this origin already produced its answer, so no
// further lane should spend anything on it.
func (b Budget) Settled(origin string) bool {
	return b.ds != nil && (b.ds.Contains(keyDone+origin) || b.ds.Contains(keyExhausted+origin))
}

// Settle marks the origin answered. It returns false if another record settled
// it first, which is how two lanes racing through the differential avoid both
// paying for the expensive stage.
func (b Budget) Settle(origin string) bool {
	return b.ds == nil || !b.ds.IsSeen(keyDone+origin)
}

// TakeRoute claims one of the origin's route-lane slots for method+path. It
// returns false when the origin is settled, when this route was already tried,
// or when the slots are used up (which also settles the origin).
func (b Budget) TakeRoute(origin, method, path string) bool {
	if b.ds == nil {
		return true
	}
	if b.Settled(origin) || b.ds.IsSeen(keyRoute+origin+"|"+method+" "+path) {
		return false
	}
	if _, ok := b.ds.IncrementAndCheck(keyRoutes+origin, MaxRoutesPerOrigin); !ok {
		b.ds.IsSeen(keyExhausted + origin)
		return false
	}
	return true
}

const (
	keyDone      = "done|"
	keyExhausted = "exhausted|"
	keyRoute     = "route|"
	keyRoutes    = "routes|"
)
