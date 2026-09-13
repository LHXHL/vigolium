package httpmsg

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestTruncateBodyInvalidatesCachedID guards the stale request hash: TruncateBody
// rewrites raw but left ID()'s memoized SHA-256 in place, so a request truncated
// after its id had been read kept reporting the pre-truncation hash — the value
// record dedup, stored-record lookup and the cluster key all rely on.
func TestTruncateBodyInvalidatesCachedID(t *testing.T) {
	raw := []byte("POST /submit HTTP/1.1\r\nHost: a.example\r\nContent-Length: 20\r\n\r\n" +
		strings.Repeat("A", 20))
	req := NewHttpRequest(append([]byte(nil), raw...))

	// Read the id first, so it is cached.
	before := req.ID()
	if before != hashOf(raw) {
		t.Fatalf("pre-truncation id does not match the raw bytes")
	}

	req.TruncateBody(5)

	after := req.ID()
	if after == before {
		t.Fatal("ID() still reports the pre-truncation hash after TruncateBody")
	}
	if want := hashOf(req.Raw()); after != want {
		t.Errorf("ID() = %s, want %s (the hash of the truncated raw bytes)", after, want)
	}

	// Repeated access is stable.
	if again := req.ID(); again != after {
		t.Errorf("ID() is not stable across calls: %s then %s", after, again)
	}
}

// Deriving the id only after truncating must agree with the truncate-then-derive
// order, so neither call order can produce a different identity.
func TestTruncateBodyIDOrderIndependent(t *testing.T) {
	raw := []byte("POST /x HTTP/1.1\r\nHost: a.example\r\n\r\n" + strings.Repeat("B", 40))

	eager := NewHttpRequest(append([]byte(nil), raw...))
	_ = eager.ID() // cache it first
	eager.TruncateBody(8)

	lazy := NewHttpRequest(append([]byte(nil), raw...))
	lazy.TruncateBody(8)

	if eager.ID() != lazy.ID() {
		t.Errorf("id depends on when it was first read: %s vs %s", eager.ID(), lazy.ID())
	}
}

// A no-op truncation must leave the cached id alone.
func TestTruncateBodyNoOpKeepsID(t *testing.T) {
	raw := []byte("POST /x HTTP/1.1\r\nHost: a.example\r\n\r\nshort")
	req := NewHttpRequest(append([]byte(nil), raw...))

	before := req.ID()
	req.TruncateBody(1000) // body already within the limit
	if after := req.ID(); after != before {
		t.Errorf("no-op truncation changed the id: %s → %s", before, after)
	}
}
