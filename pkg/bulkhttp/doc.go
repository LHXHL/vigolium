// Package bulkhttp is the multiplexing transport for request-heavy work aimed
// at one origin at a time: wordlist discovery and the fuzz primitive. The
// module scanner does not use it; it stays on HTTP/1.1 with its 1:1
// request-to-connection mapping (smuggling, header-order, raw and timing
// modules depend on that).
//
// A Transport picks one protocol per origin and keeps it, so every response a
// caller compares (a soft-404 fingerprint, a fuzz baseline) came over the same
// protocol:
//
//   - HTTP/3, when the mode allows it, the origin is https, no proxy applies,
//     and a direct QUIC handshake to the origin's port succeeds and delivers
//     the server's SETTINGS within ProbeTimeout. The handshake is the only
//     probe; it sends no HTTP request.
//   - otherwise TCP: HTTP/2 when TLS ALPN selects h2, else HTTP/1.1. Cleartext
//     http:// stays HTTP/1.1 (no h2c), and a proxied origin negotiates through
//     its CONNECT tunnel like any client.
//
// The choice is made before the origin's first request is sent. An HTTP/3
// origin whose connections keep failing is demoted to TCP for the rest of the
// Transport's life (logged once), because a scan that stops sending is worse
// than one whose protocol changed.
//
// A request whose meaning is HTTP/1.1-only - a connection-specific header
// that HTTP/2 and HTTP/3 forbid, their encoders silently drop, and whose loss
// changes what the server sees (see RequiresHTTP1) - is sent on a separate
// HTTP/1.1 transport whatever the origin's protocol.
//
// HTTP/3 connections are owned by the Transport: each is dialed on its own UDP
// socket, admitted up to StreamsPerConn concurrent requests, and retired by
// identity when it dies, so a late error from a dead connection can never
// evict its healthy replacement. More connections are opened only when every
// live one is full, up to MaxH3Conns per origin.
package bulkhttp
