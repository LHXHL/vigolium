// Package tlsprobe performs a TLS handshake against a host and reports what the
// server presented: negotiated version and cipher, and the leaf certificate's
// identity, validity window and fingerprints.
//
// It exists for the host-sweep phase, where "what certificate does this name
// serve, and is it the certificate you expected" is part of the answer — a
// wildcard shared across an estate, a cert expiring next week, a SAN list that
// names hosts the scope never mentioned. The JSON shape deliberately matches
// httpx's `tls` object so a consumer written against that output reads these
// without a mapping.
//
// Results are NOT persisted. Like the full DNS answer, a certificate is a
// property of the host rather than of any one request, and a sweep writes
// several records per host — storing it per row would put many copies of one
// identical (and TTL-stale) blob in the database. The probing run reports it
// inline; see Cached.
package tlsprobe

import (
	"context"
	"crypto/md5"  //nolint:gosec // fingerprint identity, not a security primitive
	"crypto/sha1" //nolint:gosec // fingerprint identity, not a security primitive
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// Info is one host's TLS result. Field names and JSON keys mirror httpx's `tls`
// object.
type Info struct {
	Host string `json:"host"`
	Port string `json:"port"`
	// ProbeStatus is false when the handshake did not complete, in which case
	// Error says why and every other field is empty. A failed probe is still a
	// result worth reporting — "this host does not speak TLS" is an answer.
	ProbeStatus bool   `json:"probe_status"`
	Error       string `json:"error,omitempty"`

	TLSVersion string `json:"tls_version,omitempty"`
	Cipher     string `json:"cipher,omitempty"`

	NotBefore time.Time `json:"not_before,omitempty"`
	NotAfter  time.Time `json:"not_after,omitempty"`

	SubjectDN  string   `json:"subject_dn,omitempty"`
	SubjectCN  string   `json:"subject_cn,omitempty"`
	SubjectOrg []string `json:"subject_org,omitempty"`
	SubjectAN  []string `json:"subject_an,omitempty"`

	Serial    string   `json:"serial,omitempty"`
	IssuerDN  string   `json:"issuer_dn,omitempty"`
	IssuerCN  string   `json:"issuer_cn,omitempty"`
	IssuerOrg []string `json:"issuer_org,omitempty"`

	FingerprintHash Fingerprints `json:"fingerprint_hash,omitempty"`

	// TLSConnection names the stack that performed the handshake. Always "ctls"
	// (crypto/tls) here; the field exists so the output is shape-compatible with
	// httpx, which can also report a ztls handshake.
	TLSConnection string `json:"tls_connection,omitempty"`
	// SNI is the server name actually sent. Empty for an IP literal, which is
	// not a valid SNI value.
	SNI string `json:"sni,omitempty"`
	// SelfSigned reports a certificate whose subject and issuer match. Not part
	// of httpx's object; cheap to derive here and the single most useful bit
	// when triaging a sweep's certificates.
	SelfSigned bool `json:"self_signed,omitempty"`
}

// Fingerprints holds the leaf certificate's DER digests. MD5 and SHA-1 are
// present because they are what certificate-transparency tooling and vendor
// consoles print — they are identity labels here, never a security decision.
type Fingerprints struct {
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// DefaultTimeout bounds one handshake. A sweep contacts thousands of hosts, and
// the ones that accept a connection and then stall are what set its run time.
const DefaultTimeout = 5 * time.Second

// cacheMaxEntries bounds retained results. Matches the DNS cache's bound and
// exists for the same reason: this package is linked into the long-lived ingest
// server, not only the one-shot sweep, and an Info holds two DNs, three
// fingerprints and a SAN list that is routinely 50-100 entries on a shared CDN
// certificate. An evicted host simply reads as unprobed.
const cacheMaxEntries = 8192

var cache = func() *lru.Cache[string, *Info] {
	c, _ := lru.New[string, *Info](cacheMaxEntries)
	return c
}()

// probed short-circuits the per-record cache lookup in every process that never
// probed — an export, a traffic listing, a server request. Cached is called once
// per serialized record (290k on a documented export), and without this each one
// pays a key build plus a lock for a map that is structurally empty.
var probed atomic.Bool

// cacheKey identifies a probed endpoint. The port is part of it: a host serving
// a different certificate on 8443 than on 443 is a finding, not a duplicate.
func cacheKey(host string, port int) string {
	return strings.ToLower(strings.TrimSpace(host)) + ":" + strconv.Itoa(port)
}

// Cached returns the result this PROCESS probed for host:port, or nil when it
// never did. Nil is "not probed", never "no TLS" — a host that failed the
// handshake has a non-nil Info with ProbeStatus false.
func Cached(host string, port int) *Info {
	if !probed.Load() {
		return nil
	}
	info, _ := cache.Get(cacheKey(host, port))
	return info
}

// Probe performs the handshake and caches the result, returning the cached one
// if this host:port was already probed. Safe for concurrent use.
func Probe(ctx context.Context, host string, port int, timeout time.Duration) *Info {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil
	}
	if port <= 0 {
		port = 443
	}
	key := cacheKey(host, port)

	if existing, ok := cache.Get(key); ok {
		return existing
	}

	info := handshake(ctx, host, port, timeout)

	// Another goroutine may have probed the same endpoint meanwhile; keep the
	// first result so every record for the host reports the same certificate.
	if won, loaded, _ := cache.PeekOrAdd(key, info); loaded {
		return won
	}
	probed.Store(true)
	return info
}

// handshake dials and reads the connection state. Certificate validation is
// deliberately disabled: scan targets routinely present expired, self-signed or
// wrong-host certificates, and those are exactly the results worth reporting —
// a verifying dial would refuse the connection and report nothing at all.
func handshake(ctx context.Context, host string, port int, timeout time.Duration) *Info {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	info := &Info{
		Host:          host,
		Port:          strconv.Itoa(port),
		TLSConnection: "ctls",
		SNI:           SNIName(host),
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // intentional: we inspect untrusted certs
			MinVersion:         tls.VersionTLS10,
			ServerName:         info.SNI,
		},
	}

	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialer.DialContext(dctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		info.Error = err.Error()
		return info
	}
	defer func() { _ = conn.Close() }()

	tconn, ok := conn.(*tls.Conn)
	if !ok {
		info.Error = "not a TLS connection"
		return info
	}
	state := tconn.ConnectionState()
	info.TLSVersion = versionName(state.Version)
	info.Cipher = tls.CipherSuiteName(state.CipherSuite)
	if len(state.PeerCertificates) == 0 {
		info.Error = "server presented no certificate"
		return info
	}
	info.ProbeStatus = true
	fillCert(info, state.PeerCertificates[0])
	return info
}

// fillCert copies the leaf certificate's identity into info.
func fillCert(info *Info, leaf *x509.Certificate) {
	info.NotBefore = leaf.NotBefore
	info.NotAfter = leaf.NotAfter

	info.SubjectDN = leaf.Subject.String()
	info.SubjectCN = leaf.Subject.CommonName
	info.SubjectOrg = leaf.Subject.Organization
	info.SubjectAN = subjectAltNames(leaf)

	info.IssuerDN = leaf.Issuer.String()
	info.IssuerCN = leaf.Issuer.CommonName
	info.IssuerOrg = leaf.Issuer.Organization
	info.SelfSigned = leaf.Subject.String() == leaf.Issuer.String()

	if leaf.SerialNumber != nil {
		info.Serial = formatSerial(leaf.SerialNumber.Bytes())
	}

	md5Sum := md5.Sum(leaf.Raw)   //nolint:gosec // identity label, not a security primitive
	sha1Sum := sha1.Sum(leaf.Raw) //nolint:gosec // identity label, not a security primitive
	sha256Sum := sha256.Sum256(leaf.Raw)
	info.FingerprintHash = Fingerprints{
		MD5:    hex.EncodeToString(md5Sum[:]),
		SHA1:   hex.EncodeToString(sha1Sum[:]),
		SHA256: hex.EncodeToString(sha256Sum[:]),
	}
}

// subjectAltNames flattens the certificate's DNS and IP SANs into one list, in
// certificate order. Both belong in subject_an: what a sweep wants from it is
// "what else does this certificate vouch for", and an IP SAN answers that as
// much as a DNS one.
func subjectAltNames(leaf *x509.Certificate) []string {
	if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
		return nil
	}
	out := make([]string, 0, len(leaf.DNSNames)+len(leaf.IPAddresses))
	out = append(out, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// formatSerial renders a serial as colon-separated uppercase hex, the form
// browsers, openssl and httpx all print. A zero-length serial (legal, if odd)
// renders empty rather than as a stray separator.
func formatSerial(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	parts := make([]string, len(raw))
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// versionName renders a TLS version the way httpx does ("tls13"), not the way
// Go's constants read.
func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "tls13"
	case tls.VersionTLS12:
		return "tls12"
	case tls.VersionTLS11:
		return "tls11"
	case tls.VersionTLS10:
		return "tls10"
	default:
		return fmt.Sprintf("unknown(0x%04x)", v)
	}
}

// SNIName returns the server name to send for a host. An IP literal is not a
// valid SNI value (Go drops it anyway), so such a dial goes out without one.
//
// Exported because it is one TLS wire rule with several callers — this package
// and the tls_cert_recon / tls_protocol_cipher_audit modules. Three private
// copies meant the next refinement (punycode, trailing-dot stripping, bracketed
// IPv6) would land in one and silently not the others, and the modules and the
// sweep would then send different SNI for the same host.
func SNIName(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}
