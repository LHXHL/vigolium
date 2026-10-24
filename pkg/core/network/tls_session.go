package network

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/projectdiscovery/fastdialer/fastdialer"
)

// tlsSessionCacheSize bounds the shared client session cache. One entry per
// server name the process talks to; a large multi-host scan past this simply
// falls back to full handshakes for the least recently used names.
const tlsSessionCacheSize = 4096

// sessionCache is the process-wide TLS client session cache shared by every
// target-facing transport (the scan Requester, discovery, fuzz/replay, port
// sweep). Before it existed no transport resumed a session, so every new
// connection - a pool refill, a redirect to a sibling host, a reconnect after
// an idle timeout - paid a full handshake. Resumption changes nothing at the
// HTTP layer; tools that exist to observe the handshake itself (certificate
// and cipher audits) dial with their own configs and stay off this cache.
var sessionCache = tls.NewLRUClientSessionCache(tlsSessionCacheSize)

// TLSSessionCache returns the shared client session cache.
func TLSSessionCache() tls.ClientSessionCache { return sessionCache }

// resumableFastdialerTLS is fastdialer's DefaultTLSConfig (what Dialer.DialTLS
// handshakes with) plus the shared session cache. Built once: fastdialer clones
// the config per dial, so the cache pointer is what every dial shares.
var resumableFastdialerTLS = func() *tls.Config {
	cfg := fastdialer.DefaultTLSConfig.Clone()
	cfg.ClientSessionCache = sessionCache
	return cfg
}()

// DialTLSResumable returns d.DialTLS with session resumption: the same
// handshake config, SNI handling and error behavior, through the shared cache.
// vigolium never enables fastdialer's ZTLS mode, which is the only case
// DialTLS does not use DefaultTLSConfig.
func DialTLSResumable(d *fastdialer.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.DialTLSWithConfig(ctx, network, addr, resumableFastdialerTLS)
	}
}
