package tlsprobe

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"
)

// TestProbeFailureIsReportedNotDropped: a reachable endpoint that never
// completes a handshake must surface as ProbeStatus=false WITH a reason, not as
// a nil result. "This host does not speak TLS" is an answer a sweep wants, and
// dropping it would make a plaintext service indistinguishable from one that was
// never probed.
func TestProbeFailureIsReportedNotDropped(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept and stay silent: the handshake can only time out.
			defer func() { _ = c.Close() }()
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	info := Probe(context.Background(), "127.0.0.1", port, 500*time.Millisecond)
	if info == nil {
		t.Fatal("Probe returned nil for a reachable-but-not-TLS endpoint")
	}
	if info.ProbeStatus {
		t.Error("ProbeStatus = true against a listener that never completes a handshake")
	}
	if info.Error == "" {
		t.Error("a failed probe must say why")
	}
	// An IP literal is not a valid SNI value — Go drops it, so it must not be sent.
	if info.SNI != "" {
		t.Errorf("SNI = %q for an IP literal, want empty", info.SNI)
	}
	// Cached even on failure: re-probing per record would multiply the timeout
	// across every row for the host.
	if Cached("127.0.0.1", port) == nil {
		t.Error("a failed probe must still be cached")
	}
}

// TestProbeReadsSelfSignedCertificate proves validation is disabled on purpose:
// an untrusted certificate is the result, not an error. A verifying dial would
// refuse the connection and report nothing about a cert worth reporting.
func TestProbeReadsSelfSignedCertificate(t *testing.T) {
	cert := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				_ = c.Close()
			}()
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	info := Probe(context.Background(), "127.0.0.1", port, 5*time.Second)
	if info == nil || !info.ProbeStatus {
		t.Fatalf("probe failed against a self-signed server: %+v", info)
	}
	if info.SubjectCN != "probe.test" {
		t.Errorf("subject_cn = %q, want probe.test", info.SubjectCN)
	}
	if !info.SelfSigned {
		t.Error("self_signed = false for a certificate whose subject equals its issuer")
	}
	if info.TLSVersion == "" || info.Cipher == "" {
		t.Errorf("negotiated version/cipher missing: %q / %q", info.TLSVersion, info.Cipher)
	}
	if info.FingerprintHash.SHA256 == "" {
		t.Error("sha256 fingerprint missing")
	}
	if info.TLSConnection != "ctls" {
		t.Errorf("tls_connection = %q, want ctls", info.TLSConnection)
	}
}

// TestFormatSerial pins the colon-separated uppercase hex form that browsers,
// openssl and httpx all print, so a serial can be pasted between them.
func TestFormatSerial(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty renders empty, not a stray separator", nil, ""},
		{"single byte", []byte{0x02}, "02"},
		{"zero-pads", []byte{0x02, 0x62, 0xef}, "02:62:EF"},
		{"uppercase", []byte{0xab, 0xcd}, "AB:CD"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatSerial(tt.in); got != tt.want {
				t.Errorf("formatSerial(%x) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestVersionName pins httpx's spellings rather than Go's constant names — the
// whole point of the shape is that an httpx consumer reads it unmodified.
func TestVersionName(t *testing.T) {
	for v, want := range map[uint16]string{
		tls.VersionTLS13: "tls13",
		tls.VersionTLS12: "tls12",
		tls.VersionTLS11: "tls11",
		tls.VersionTLS10: "tls10",
	} {
		if got := versionName(v); got != want {
			t.Errorf("versionName(%#x) = %q, want %q", v, got, want)
		}
	}
	if got := versionName(0x9999); got == "" {
		t.Error("an unknown version must still render something identifiable")
	}
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsaKey()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1234),
		Subject:      pkix.Name{CommonName: "probe.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"probe.test"},
	}
	der, err := x509.CreateCertificate(cryptoRand(), tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func rsaKey() (*rsa.PrivateKey, error) { return rsa.GenerateKey(cryptoRand(), 2048) }
func cryptoRand() io.Reader            { return rand.Reader }
