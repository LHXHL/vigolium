package recon

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math/bits"
	"strconv"
	"strings"
)

// FaviconInfo is one origin's favicon, hashed the ways the internet-wide search
// engines index it, so a value pivots straight into a query.
type FaviconInfo struct {
	// URL is where the icon was fetched: the page's <link rel="icon"> when it
	// names one on the same origin, /favicon.ico otherwise.
	URL string `json:"url"`
	// MMH3 is Shodan's http.favicon.hash and FOFA's icon_hash: murmur3 x86 32
	// (seed 0, signed) over the body's base64 wrapped at 76 characters with a
	// newline after every line, the last included — Python's
	// base64.encodebytes, which is what those engines hashed.
	MMH3 int32 `json:"mmh3"`
	// MD5 is the raw body's MD5 (Censys services.http.response.favicons.md5_hash).
	MD5    string `json:"md5"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

// ShodanQuery and FOFAQuery are the search expressions the hash pivots on.
func (f *FaviconInfo) ShodanQuery() string { return "http.favicon.hash:" + itoa32(f.MMH3) }
func (f *FaviconInfo) FOFAQuery() string   { return `icon_hash="` + itoa32(f.MMH3) + `"` }

func itoa32(v int32) string { return strconv.FormatInt(int64(v), 10) }

// WrappedBase64 is Python's base64.encodebytes: 76-character lines, each
// followed by a newline (the last one too). Empty input encodes to nothing.
func WrappedBase64(b []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(b)
	var out bytes.Buffer
	for i := 0; i < len(enc); i += 76 {
		end := min(i+76, len(enc))
		out.WriteString(enc[i:end])
		out.WriteByte('\n')
	}
	return out.Bytes()
}

// ShodanFaviconHash is the mmh3 value Shodan and FOFA index for an icon body.
func ShodanFaviconHash(body []byte) int32 {
	return int32(Murmur3x86_32(WrappedBase64(body), 0))
}

// Murmur3x86_32 is MurmurHash3's x86 32-bit variant, the function Python's
// mmh3.hash computes (signed there). Written out rather than imported: the
// common Go package reads blocks through unaligned unsafe pointers, which the
// race detector's checkptr rejects.
func Murmur3x86_32(data []byte, seed uint32) uint32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	h := seed
	blocks := len(data) / 4
	for i := 0; i < blocks; i++ {
		k := binary.LittleEndian.Uint32(data[i*4:])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}
	var k uint32
	switch tail := data[blocks*4:]; len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// HashFavicon hashes one icon body fetched from url.
func HashFavicon(url string, body []byte) *FaviconInfo {
	m := md5.Sum(body) //nolint:gosec // an index key, not a security control
	s := sha256.Sum256(body)
	return &FaviconInfo{
		URL:    url,
		MMH3:   ShodanFaviconHash(body),
		MD5:    hex.EncodeToString(m[:]),
		SHA256: hex.EncodeToString(s[:]),
		Size:   len(body),
	}
}

// LooksLikeIcon reports whether body is an image an icon link can serve (ICO,
// CUR, PNG, GIF, JPEG, BMP, WebP or SVG) by its magic bytes. A soft-404 HTML
// page answering /favicon.ico with 200 hashes to a value that matches every
// other host serving the same error page, which is worse than no hash.
func LooksLikeIcon(body []byte) bool {
	if len(body) < 4 {
		return false
	}
	b := body
	switch {
	case b[0] == 0 && b[1] == 0 && (b[2] == 1 || b[2] == 2) && b[3] == 0:
		return true
	case b[0] == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G':
		return true
	case b[0] == 'G' && b[1] == 'I' && b[2] == 'F':
		return true
	case b[0] == 0xff && b[1] == 0xd8 && b[2] == 0xff:
		return true
	case b[0] == 'B' && b[1] == 'M':
		return true
	case len(b) >= 12 && string(b[0:4]) == "RIFF" && string(b[8:12]) == "WEBP":
		return true
	}
	head := strings.ToLower(string(b[:min(512, len(b))]))
	return strings.Contains(head, "<svg") && !strings.Contains(head, "<html")
}
