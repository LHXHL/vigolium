package infra

import (
	"fmt"
	"strings"
)

// HostHeaderVariant is one request header through which a client can steer the
// host (or scheme/port/client address) an application believes it is serving.
// Modules that probe host trust share this table so the header set and value
// shapes stay in one place: host_header_injection reflects every variant, and
// password_reset_poisoning plants a callback host in the link-building subset.
type HostHeaderVariant struct {
	// Header is the request header name.
	Header string
	// Format renders the header value. %s is replaced by the injected host;
	// a Format without %s is a fixed literal (X-Forwarded-Proto: nothttps)
	// that carries no host at all.
	Format string
	// Desc is a short human description used in finding text.
	Desc string
	// BuildsLinks marks the headers web frameworks commonly read when building
	// absolute URLs (password-reset links, redirects, canonical links): Host,
	// X-Forwarded-Host, X-Host and RFC 7239 Forwarded.
	BuildsLinks bool
}

// Value renders the header value for host. Literal variants ignore host.
func (v HostHeaderVariant) Value(host string) string {
	if strings.Contains(v.Format, "%s") {
		return fmt.Sprintf(v.Format, host)
	}
	return v.Format
}

// CarriesHost reports whether the variant's value embeds the injected host.
func (v HostHeaderVariant) CarriesHost() bool { return strings.Contains(v.Format, "%s") }

// HostHeaderVariants is the shared host-override header table, in probe order.
var HostHeaderVariants = []HostHeaderVariant{
	{Header: "Host", Format: "%s", Desc: "Direct Host header override", BuildsLinks: true},
	{Header: "X-Forwarded-Host", Format: "%s", Desc: "X-Forwarded-Host header injection", BuildsLinks: true},
	{Header: "X-Host", Format: "%s", Desc: "X-Host header injection", BuildsLinks: true},
	{Header: "X-Original-URL", Format: "%s", Desc: "X-Original-URL header injection"},
	{Header: "Forwarded", Format: "host=%s", Desc: "RFC 7239 Forwarded header injection", BuildsLinks: true},
	{Header: "X-Forwarded-Proto", Format: "nothttps", Desc: "X-Forwarded-Proto header injection"},
	{Header: "X-Forwarded-Port", Format: "1337", Desc: "X-Forwarded-Port header injection"},
	{Header: "X-Real-IP", Format: "%s", Desc: "X-Real-IP header injection"},
	{Header: "Cf-Connecting-IP", Format: "%s", Desc: "Cloudflare Cf-Connecting-IP header injection"},
}

// LinkHostHeaderVariants returns the HostHeaderVariants that frameworks read
// when building absolute URLs (BuildsLinks), in table order. The slice is a
// fresh copy, safe for the caller to modify.
func LinkHostHeaderVariants() []HostHeaderVariant {
	out := make([]HostHeaderVariant, 0, 4)
	for _, v := range HostHeaderVariants {
		if v.BuildsLinks {
			out = append(out, v)
		}
	}
	return out
}
