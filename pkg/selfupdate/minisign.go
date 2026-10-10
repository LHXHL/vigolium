package selfupdate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// minisign.go verifies minisign signatures (https://jedisct1.github.io/minisign/)
// with crypto/ed25519. The format is small enough that a full dependency is not
// worth it:
//
//	public key  = base64( "Ed" | key_id[8] | ed25519_pub[32] )
//	.minisig    = "untrusted comment: <text>\n"
//	              base64( alg[2] | key_id[8] | sig[64] ) "\n"
//	              "trusted comment: <text>\n"
//	              base64( global_sig[64] ) "\n"
//
// alg "Ed" signs the file itself; alg "ED" (the minisign >= 0.10 default) signs
// BLAKE2b-512(file). global_sig signs sig || trusted_comment, which is what
// makes the trusted comment trustworthy.

var (
	algEd       = [2]byte{'E', 'd'} // legacy: ed25519 over the raw message
	algHashedEd = [2]byte{'E', 'D'} // prehashed: ed25519 over BLAKE2b-512(message)
)

const (
	untrustedPrefix = "untrusted comment: "
	trustedPrefix   = "trusted comment: "
)

// ErrBadSignature is returned when no trusted key verifies a signature.
var ErrBadSignature = errors.New("signature verification failed")

// publicKey is a parsed minisign public key.
type publicKey struct {
	id  [8]byte
	key ed25519.PublicKey
}

// parsePublicKey accepts either the bare base64 line ("RWQ…") or a whole
// minisign.pub file (untrusted comment line + base64 line).
func parsePublicKey(text string) (publicKey, error) {
	text = strings.TrimSpace(text)
	if i := strings.LastIndexByte(text, '\n'); i >= 0 {
		if !strings.HasPrefix(text, untrustedPrefix) {
			return publicKey{}, errors.New("minisign public key: unexpected multi-line text")
		}
		text = strings.TrimSpace(text[i+1:])
	}
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return publicKey{}, fmt.Errorf("minisign public key: %w", err)
	}
	if len(raw) != 2+8+ed25519.PublicKeySize {
		return publicKey{}, fmt.Errorf("minisign public key: length %d, want %d", len(raw), 2+8+ed25519.PublicKeySize)
	}
	if !bytes.Equal(raw[:2], algEd[:]) {
		return publicKey{}, errors.New("minisign public key: not an Ed25519 key")
	}
	var pk publicKey
	copy(pk.id[:], raw[2:10])
	pk.key = ed25519.PublicKey(bytes.Clone(raw[10:]))
	return pk, nil
}

// signature is a parsed .minisig file.
type signature struct {
	alg            [2]byte
	keyID          [8]byte
	sig            []byte
	trustedComment string
	globalSig      []byte
}

func parseSignature(data []byte) (signature, error) {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	// Trailing newline(s) produce empty tail elements.
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) != 4 {
		return signature{}, fmt.Errorf("minisign signature: %d lines, want 4", len(lines))
	}
	if !strings.HasPrefix(lines[0], untrustedPrefix) {
		return signature{}, errors.New("minisign signature: missing untrusted comment")
	}
	if !strings.HasPrefix(lines[2], trustedPrefix) {
		return signature{}, errors.New("minisign signature: missing trusted comment")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil {
		return signature{}, fmt.Errorf("minisign signature: %w", err)
	}
	if len(raw) != 2+8+ed25519.SignatureSize {
		return signature{}, fmt.Errorf("minisign signature: length %d, want %d", len(raw), 2+8+ed25519.SignatureSize)
	}
	global, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[3]))
	if err != nil {
		return signature{}, fmt.Errorf("minisign signature: global signature: %w", err)
	}
	if len(global) != ed25519.SignatureSize {
		return signature{}, fmt.Errorf("minisign signature: global signature length %d, want %d", len(global), ed25519.SignatureSize)
	}
	var s signature
	copy(s.alg[:], raw[:2])
	if s.alg != algEd && s.alg != algHashedEd {
		return signature{}, fmt.Errorf("minisign signature: unknown algorithm %q", s.alg[:])
	}
	copy(s.keyID[:], raw[2:10])
	s.sig = raw[10:]
	s.trustedComment = strings.TrimPrefix(lines[2], trustedPrefix)
	s.globalSig = global
	return s, nil
}

// verifyWith checks sig over message with one key: key ID, file signature and
// the global (trusted comment) signature must all match.
func (s signature) verifyWith(pk publicKey, message []byte) bool {
	if s.keyID != pk.id {
		return false
	}
	signed := message
	if s.alg == algHashedEd {
		sum := blake2b.Sum512(message)
		signed = sum[:]
	}
	if !ed25519.Verify(pk.key, signed, s.sig) {
		return false
	}
	global := append(bytes.Clone(s.sig), s.trustedComment...)
	return ed25519.Verify(pk.key, global, s.globalSig)
}

// verifyMinisign verifies sigData over message against any of keys and returns
// the signature's trusted comment. Keys that do not parse are skipped (the
// placeholder slots in keys.go); when none parse it fails with ErrNoTrustedKeys.
func verifyMinisign(keys []string, message, sigData []byte) (string, error) {
	var parsed []publicKey
	for _, k := range keys {
		if pk, err := parsePublicKey(k); err == nil {
			parsed = append(parsed, pk)
		}
	}
	if len(parsed) == 0 {
		return "", ErrNoTrustedKeys
	}
	sig, err := parseSignature(sigData)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	for _, pk := range parsed {
		if sig.verifyWith(pk, message) {
			return sig.trustedComment, nil
		}
	}
	return "", fmt.Errorf("%w: checksums.txt is not signed by a trusted release key", ErrBadSignature)
}
