package http

import (
	"net/http"
	"slices"
	"strings"

	"github.com/vigolium/vigolium/pkg/reconsig"
	"github.com/vigolium/vigolium/pkg/types"
)

// Redirect modes accepted by Options.RedirectMode / --redirect-mode.
//
// These replace the FollowRedirects/FollowHostRedirects bool pair, which had no
// spelling for the case a host sweep needs: follow inside the registrable
// domain. `www.example.com -> example.com` is the same application answering
// under its canonical name, while `example.com -> tracker.example.net` is a
// different party — and exact-host matching cannot tell those apart, so the
// only options were "follow everything" or "follow nothing".
const (
	// RedirectModeOff records the 3xx itself and never follows it.
	RedirectModeOff = "off"
	// RedirectModeSameHost follows only when scheme-host-port is unchanged.
	RedirectModeSameHost = "same-host"
	// RedirectModeSameApex follows while the registrable domain (eTLD+1) is
	// unchanged. Cross-scheme and cross-port hops within that domain follow.
	RedirectModeSameApex = "same-apex"
	// RedirectModeAny follows every redirect up to the hop cap. This is the
	// historical default and stays the default, so no existing scan changes
	// behaviour by upgrading.
	RedirectModeAny = "any"
)

// RedirectModes lists every accepted spelling, in the order help text should
// present them (most restrictive first). Error messages derive from this rather
// than hand-listing, so a mode added here reaches the CLI for free.
var RedirectModes = []string{
	RedirectModeOff,
	RedirectModeSameHost,
	RedirectModeSameApex,
	RedirectModeAny,
}

// ValidRedirectMode reports whether s names a redirect mode.
func ValidRedirectMode(s string) bool {
	return slices.Contains(RedirectModes, strings.ToLower(strings.TrimSpace(s)))
}

// ResolveRedirectMode collapses the redirect options into one mode.
//
// An explicit RedirectMode always wins. Otherwise the legacy bools are mapped
// so nothing that set them changes behaviour: DisableRedirects means off,
// FollowHostRedirects means same-host, and anything else means any — which is
// what the old makeRedirectFunc(false, n) already did, since it only ever
// refused on the hop cap.
func ResolveRedirectMode(options *types.Options) string {
	if options == nil {
		return RedirectModeAny
	}
	if m := strings.ToLower(strings.TrimSpace(options.RedirectMode)); m != "" {
		if ValidRedirectMode(m) {
			return m
		}
		// An unrecognised value is caught at flag-validation time; falling back
		// to the historical default here keeps a library caller that set it by
		// hand from silently getting "follow nothing".
		return RedirectModeAny
	}
	switch {
	case options.DisableRedirects:
		return RedirectModeOff
	case options.FollowHostRedirects:
		return RedirectModeSameHost
	default:
		return RedirectModeAny
	}
}

// makeRedirectFunc builds the http.Client CheckRedirect policy for mode.
//
// via[0] is the ORIGINAL request, not the previous hop: a chain that walks
// a.example -> b.example -> c.example is judged against a.example at every
// step. That is deliberate for same-apex — otherwise a chain could walk off
// its starting domain one hop at a time, each hop looking legitimate relative
// to the one before it.
func makeRedirectFunc(mode string, maxRedirects int) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return http.ErrUseLastResponse
		}
		switch mode {
		case RedirectModeOff:
			return http.ErrUseLastResponse
		case RedirectModeSameHost:
			if req.URL.Host != via[0].URL.Host {
				return http.ErrUseLastResponse
			}
		case RedirectModeSameApex:
			if !sameRegistrableDomain(via[0].URL.Host, req.URL.Host) {
				return http.ErrUseLastResponse
			}
		}
		return nil
	}
}

// sameRegistrableDomain reports whether two hosts share an eTLD+1.
//
// Fails CLOSED: when either host has no resolvable registrable domain (a bare
// IP, an internal single-label name like "intranet", an unparseable host), the
// answer is exact-host equality. Following a redirect is a request to a new
// destination, so "I could not tell" must not resolve to "go ahead" — an IP
// literal in particular has no apex at all, and treating an unresolvable pair
// as same-apex would make every such hop follow unconditionally.
func sameRegistrableDomain(fromHost, toHost string) bool {
	// reconsig normalizes (lowercase, trim, strip port) on the way in, so both
	// helpers are handed the raw host as-is.
	fromAPEX := reconsig.RegistrableDomain(fromHost)
	toAPEX := reconsig.RegistrableDomain(toHost)
	if fromAPEX == "" || toAPEX == "" {
		// Compare the bare hostnames (port stripped) so a bare-IP target that
		// redirects to itself on another port still follows.
		return reconsig.HostOf(fromHost) == reconsig.HostOf(toHost)
	}
	return fromAPEX == toAPEX
}
