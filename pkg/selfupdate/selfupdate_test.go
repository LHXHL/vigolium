package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// --- minisign test key -------------------------------------------------------
//
// testSigner is a throwaway key used only by these tests. It is NOT and must
// never be one of the built-in trustedKeys.

type testSigner struct {
	id   [8]byte
	priv ed25519.PrivateKey
}

func newTestSigner(seedByte byte) testSigner {
	seed := bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)
	s := testSigner{priv: ed25519.NewKeyFromSeed(seed)}
	copy(s.id[:], bytes.Repeat([]byte{seedByte ^ 0x5a}, 8))
	return s
}

func (s testSigner) publicKey() string {
	raw := append(append(append([]byte{}, algEd[:]...), s.id[:]...), s.priv.Public().(ed25519.PublicKey)...)
	return base64.StdEncoding.EncodeToString(raw)
}

// sign produces a .minisig for msg, prehashed like minisign >= 0.10.
func (s testSigner) sign(msg []byte, trustedComment string) []byte {
	sum := blake2b.Sum512(msg)
	sig := ed25519.Sign(s.priv, sum[:])
	raw := append(append(append([]byte{}, algHashedEd[:]...), s.id[:]...), sig...)
	global := ed25519.Sign(s.priv, append(bytes.Clone(sig), trustedComment...))
	return []byte("untrusted comment: signature from minisign secret key\n" +
		base64.StdEncoding.EncodeToString(raw) + "\n" +
		"trusted comment: " + trustedComment + "\n" +
		base64.StdEncoding.EncodeToString(global) + "\n")
}

// --- golden vectors produced by aead.dev/minisign ---------------------------

func TestVerifyMinisignGoldenLegacy(t *testing.T) {
	// From aead.dev/minisign's ExampleVerify: algorithm "Ed" (unhashed).
	const pub = "RWQGPaMY2ls0CkF/83ls7D+IU25w3jeYczwo3s451zDlnrJJwOdt2ro8"
	sig := []byte(`untrusted comment: signature from private key: A345BDA18A33D06
RWQGPaMY2ls0CmMflCAP5J/MpaXmt+3+UoT1vRSPRjXO6w0KNtpkcQe3TxQ35kAwhjFVB6CEYYrHZmMvWjXRutefRHicRUiAJwQ=
trusted comment: timestamp:1600100266
2x/lxCqL+PHoT4I9Wc8PHmoNBtohgmFdWwPBON55Y2P0ttpBHgr4OFldr/Hq7nDcBGt5SBs2XjtMnxjVs6byBg==`)
	comment, err := verifyMinisign([]string{pub}, []byte("Hello Gopher!"), sig)
	if err != nil {
		t.Fatalf("golden legacy signature rejected: %v", err)
	}
	if comment != "timestamp:1600100266" {
		t.Errorf("trusted comment = %q", comment)
	}
	if _, err := verifyMinisign([]string{pub}, []byte("Hello Gopher?"), sig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered message: err = %v, want ErrBadSignature", err)
	}
}

func TestVerifyMinisignGoldenPrehashed(t *testing.T) {
	// Generated with aead.dev/minisign Reader.SignWithComments (algorithm "ED",
	// BLAKE2b-512 prehash) — the format `minisign -S` writes today.
	pubFile := "untrusted comment: minisign public key: 44C72701261C2D8D\nRWSNLRwmASfHROpKbGPinFIKvvVQexMuxfmVR3auvr57kkIe6mkURtIs\n"
	msg := []byte("abc123  vigolium_1.2.3_linux_amd64.tar.gz\n")
	sig := []byte(`untrusted comment: signature from minisign secret key
RUSNLRwmASfHRG0CbXysO78VxLgUVosFDq5hZv0T8vGVWXxWhlmhUYs1mcOEHDUr7mhtUX5lmWuxyw4lm4IeS6k5zhMRAscJTgg=
trusted comment: vigolium v1.2.3
NIXHYElXfADlQI3Auiwh6P9aP/oIV8YIi3vvvlZ0nH6cQM5dGxPu9u39F63bL/PI+GcJRE70o75cEpQNyHAtDw==
`)
	comment, err := verifyMinisign([]string{pubFile}, msg, sig)
	if err != nil {
		t.Fatalf("golden prehashed signature rejected: %v", err)
	}
	if comment != "vigolium v1.2.3" || !commentNamesVersion(comment, "1.2.3") {
		t.Errorf("trusted comment = %q", comment)
	}

	// The trusted comment is covered by the global signature.
	forged := bytes.Replace(sig, []byte("vigolium v1.2.3"), []byte("vigolium v9.9.9"), 1)
	if _, err := verifyMinisign([]string{pubFile}, msg, forged); !errors.Is(err, ErrBadSignature) {
		t.Errorf("forged trusted comment: err = %v, want ErrBadSignature", err)
	}
	// Another key, even a valid one, does not verify it.
	other := newTestSigner(9).publicKey()
	if _, err := verifyMinisign([]string{other}, msg, sig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("wrong key: err = %v, want ErrBadSignature", err)
	}
}

func TestVerifyMinisignPlaceholderKeysFailClosed(t *testing.T) {
	s := newTestSigner(1)
	msg := []byte("x")
	if _, err := verifyMinisign([]string{"TODO-placeholder", ""}, msg, s.sign(msg, "c")); !errors.Is(err, ErrNoTrustedKeys) {
		t.Fatalf("placeholder-only keys: err = %v, want ErrNoTrustedKeys", err)
	}
}

func TestVerifyMinisignNextKeySlot(t *testing.T) {
	current, next := newTestSigner(1), newTestSigner(2)
	msg := []byte("checksums")
	// Signed with the rotation ("next") key: still trusted.
	if _, err := verifyMinisign([]string{current.publicKey(), next.publicKey()}, msg, next.sign(msg, "c")); err != nil {
		t.Fatalf("next-slot signature rejected: %v", err)
	}
}

// --- release fixture ---------------------------------------------------------

const (
	oldVersion = "v1.2.2"
	newVersion = "v1.2.3"
)

type release struct {
	mu       sync.Mutex
	files    map[string][]byte
	requests []string
}

func (r *release) handler(w http.ResponseWriter, req *http.Request) {
	name := strings.TrimPrefix(req.URL.Path, "/")
	r.mu.Lock()
	r.requests = append(r.requests, name)
	data, ok := r.files[name]
	r.mu.Unlock()
	if !ok {
		http.NotFound(w, req)
		return
	}
	_, _ = w.Write(data)
}

func (r *release) requested(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.requests {
		if n == name {
			return true
		}
	}
	return false
}

// fakeBinary is a shell script standing in for a release binary: it answers
// `version --json` with the given version.
func fakeBinary(version string) []byte {
	return []byte(fmt.Sprintf("#!/bin/sh\necho '{\"version\":\"%s\",\"commit\":\"abc\"}'\n", version))
}

type tarEntry struct {
	name string
	body []byte
}

func tarGz(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o755, Size: int64(len(e.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zipArchive(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// newRelease builds a signed v1.2.3 release for linux/amd64-style unix
// archives (the archive name uses the running GOOS/GOARCH so the real version
// check can execute the extracted script).
func newRelease(t *testing.T, signer testSigner, binary []byte) (*release, string) {
	t.Helper()
	archive := archiveName(newVersion, runtime.GOOS, runtime.GOARCH)
	data := tarGz(t,
		tarEntry{"LICENSE", []byte("license")},
		tarEntry{"vigolium", binary},
		tarEntry{"THIRD_PARTY_NOTICES.md", []byte("notices")},
	)
	sums := []byte(fmt.Sprintf("%s  %s\n%s  vigolium_1.2.3_other_arch.tar.gz\n", sha(data), archive, strings.Repeat("0", 64)))
	r := &release{files: map[string][]byte{
		"metadata.json":         []byte(`{"version":"` + newVersion + `","commit":"abc","build_time":"now"}`),
		"checksums.txt":         sums,
		"checksums.txt.minisig": signer.sign(sums, "vigolium "+newVersion),
		archive:                 data,
	}}
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	t.Cleanup(srv.Close)
	return r, srv.URL
}

// installed writes an "old" binary into a fresh dir and returns its path.
func installed(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "vigolium")
	if err := os.WriteFile(p, fakeBinary(oldVersion), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func requireUnixExec(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake release binary is a shell script")
	}
}

func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tempPrefix) {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}
}

func assertUnchanged(t *testing.T, path string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, fakeBinary(oldVersion)) {
		t.Errorf("%s was modified", path)
	}
}

func baseOpts(url string, signer testSigner, target string) Options {
	return Options{
		BaseURL:        url,
		CurrentVersion: oldVersion,
		Target:         target,
		TrustedKeys:    []string{signer.publicKey()},
	}
}

// --- Update ------------------------------------------------------------------

func TestUpdateReplacesInstalledBinary(t *testing.T) {
	requireUnixExec(t)
	signer := newTestSigner(1)
	_, url := newRelease(t, signer, fakeBinary(newVersion))
	target := installed(t)

	res, err := Update(context.Background(), baseOpts(url, signer, target))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !res.Changed || res.From != oldVersion || res.To != newVersion || res.Path != mustResolve(t, target) {
		t.Errorf("result = %+v", res)
	}
	got, _ := os.ReadFile(target)
	if !bytes.Equal(got, fakeBinary(newVersion)) {
		t.Errorf("target not replaced: %q", got)
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm()&0o111 == 0 {
		t.Errorf("replaced binary is not executable: %v", fi.Mode())
	}
	assertNoTempFiles(t, filepath.Dir(target))
}

func mustResolve(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(r)
	return abs
}

func TestUpdateFollowsSymlinkToRealBinary(t *testing.T) {
	requireUnixExec(t)
	signer := newTestSigner(1)
	_, url := newRelease(t, signer, fakeBinary(newVersion))
	real := installed(t)
	link := filepath.Join(t.TempDir(), "vigolium")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	res, err := Update(context.Background(), baseOpts(url, signer, link))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if res.Path != mustResolve(t, real) {
		t.Errorf("Path = %s, want the symlink's target %s", res.Path, real)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("symlink was replaced instead of its target")
	}
	got, _ := os.ReadFile(real)
	if !bytes.Equal(got, fakeBinary(newVersion)) {
		t.Errorf("real binary not replaced")
	}
}

func TestUpdateRejectsBadSignature(t *testing.T) {
	signer := newTestSigner(1)
	r, url := newRelease(t, signer, fakeBinary(newVersion))
	r.files["checksums.txt.minisig"] = newTestSigner(7).sign(r.files["checksums.txt"], "vigolium "+newVersion)
	target := installed(t)

	_, err := Update(context.Background(), baseOpts(url, signer, target))
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
	if r.requested(archiveName(newVersion, runtime.GOOS, runtime.GOARCH)) {
		t.Errorf("archive downloaded despite a bad signature")
	}
	assertUnchanged(t, target)
	assertNoTempFiles(t, filepath.Dir(target))
}

func TestUpdateRejectsMissingSignature(t *testing.T) {
	signer := newTestSigner(1)
	r, url := newRelease(t, signer, fakeBinary(newVersion))
	delete(r.files, "checksums.txt.minisig")
	target := installed(t)
	if _, err := Update(context.Background(), baseOpts(url, signer, target)); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("err = %v, want a not-signed error", err)
	}
	assertUnchanged(t, target)
}

func TestUpdateRejectsSignatureForOtherVersion(t *testing.T) {
	signer := newTestSigner(1)
	r, url := newRelease(t, signer, fakeBinary(newVersion))
	r.files["checksums.txt.minisig"] = signer.sign(r.files["checksums.txt"], "vigolium v1.0.0")
	target := installed(t)
	if _, err := Update(context.Background(), baseOpts(url, signer, target)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
	assertUnchanged(t, target)
}

func TestUpdateRejectsWrongSHA(t *testing.T) {
	signer := newTestSigner(1)
	r, url := newRelease(t, signer, fakeBinary(newVersion))
	archive := archiveName(newVersion, runtime.GOOS, runtime.GOARCH)
	r.files[archive] = tarGz(t, tarEntry{"vigolium", []byte("tampered")})
	target := installed(t)
	_, err := Update(context.Background(), baseOpts(url, signer, target))
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("err = %v, want sha256 mismatch", err)
	}
	assertUnchanged(t, target)
	assertNoTempFiles(t, filepath.Dir(target))
}

func TestUpdateRejectsWrongReportedVersion(t *testing.T) {
	requireUnixExec(t)
	signer := newTestSigner(1)
	_, url := newRelease(t, signer, fakeBinary("v9.9.9"))
	target := installed(t)
	_, err := Update(context.Background(), baseOpts(url, signer, target))
	if err == nil || !strings.Contains(err.Error(), "reports version v9.9.9") {
		t.Fatalf("err = %v, want a version mismatch", err)
	}
	assertUnchanged(t, target)
	assertNoTempFiles(t, filepath.Dir(target))
}

func TestUpdateRejectsOversizeEntry(t *testing.T) {
	signer := newTestSigner(1)
	_, url := newRelease(t, signer, fakeBinary(newVersion))
	target := installed(t)
	opts := baseOpts(url, signer, target)
	opts.MaxBinaryBytes = 8
	_, err := Update(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("err = %v, want a size-limit error", err)
	}
	assertUnchanged(t, target)
	assertNoTempFiles(t, filepath.Dir(target))
}

func TestUpdateRejectsOversizeArchive(t *testing.T) {
	signer := newTestSigner(1)
	_, url := newRelease(t, signer, fakeBinary(newVersion))
	target := installed(t)
	opts := baseOpts(url, signer, target)
	opts.MaxArchiveBytes = 16
	if _, err := Update(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("err = %v, want a size-limit error", err)
	}
	assertUnchanged(t, target)
}

func TestUpdateNoopWhenCurrent(t *testing.T) {
	signer := newTestSigner(1)
	r, url := newRelease(t, signer, fakeBinary(newVersion))
	target := installed(t)
	opts := baseOpts(url, signer, target)
	opts.CurrentVersion = newVersion
	res, err := Update(context.Background(), opts)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if res.Changed || res.UpdateAvailable {
		t.Errorf("result = %+v, want no change", res)
	}
	if r.requested("checksums.txt") {
		t.Errorf("fetched checksums although already current")
	}
	assertUnchanged(t, target)
}

func TestUpdateDryRunWritesNothing(t *testing.T) {
	signer := newTestSigner(1)
	r, url := newRelease(t, signer, fakeBinary(newVersion))
	target := installed(t)
	opts := baseOpts(url, signer, target)
	opts.DryRun = true
	res, err := Update(context.Background(), opts)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if res.Changed || !res.UpdateAvailable || res.SHA256 == "" || !res.DryRun {
		t.Errorf("result = %+v", res)
	}
	if r.requested(res.Archive) {
		t.Errorf("dry run downloaded the archive")
	}
	assertUnchanged(t, target)
	assertNoTempFiles(t, filepath.Dir(target))
}

func TestUpdateNonWritableTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions differ on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	signer := newTestSigner(1)
	r, url := newRelease(t, signer, fakeBinary(newVersion))
	target := installed(t)
	dir := filepath.Dir(target)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	_, err := Update(context.Background(), baseOpts(url, signer, target))
	var nw *NotWritableError
	if !errors.As(err, &nw) {
		t.Fatalf("err = %v, want NotWritableError", err)
	}
	for _, want := range []string{"not writable", "sudo", "--install-dir"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if r.requested(archiveName(newVersion, runtime.GOOS, runtime.GOARCH)) {
		t.Errorf("downloaded although the target is not writable")
	}
	assertUnchanged(t, target)
}

func TestUpdateInstallDir(t *testing.T) {
	requireUnixExec(t)
	signer := newTestSigner(1)
	_, url := newRelease(t, signer, fakeBinary(newVersion))
	running := installed(t)
	dir := filepath.Join(t.TempDir(), "custom", "bin")
	opts := baseOpts(url, signer, running)
	opts.InstallDir = dir
	res, err := Update(context.Background(), opts)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	want := filepath.Join(dir, "vigolium")
	if res.Path != want {
		t.Errorf("Path = %s, want %s", res.Path, want)
	}
	if got, _ := os.ReadFile(want); !bytes.Equal(got, fakeBinary(newVersion)) {
		t.Errorf("install dir copy not written")
	}
	assertUnchanged(t, running)
}

func TestUpdateRejectsDuplicateEntries(t *testing.T) {
	signer := newTestSigner(1)
	r, url := newRelease(t, signer, fakeBinary(newVersion))
	archive := archiveName(newVersion, runtime.GOOS, runtime.GOARCH)
	data := tarGz(t, tarEntry{"vigolium", fakeBinary(newVersion)}, tarEntry{"sub/vigolium", []byte("second")})
	sums := []byte(fmt.Sprintf("%s  %s\n", sha(data), archive))
	r.files[archive] = data
	r.files["checksums.txt"] = sums
	r.files["checksums.txt.minisig"] = signer.sign(sums, "vigolium "+newVersion)
	target := installed(t)
	if _, err := Update(context.Background(), baseOpts(url, signer, target)); err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Fatalf("err = %v, want a duplicate-entry error", err)
	}
	assertUnchanged(t, target)
}

func TestUpdateBuiltInPlaceholderKeysFailClosed(t *testing.T) {
	if TrustedKeysConfigured() {
		t.Skip("real release keys are configured")
	}
	signer := newTestSigner(1)
	_, url := newRelease(t, signer, fakeBinary(newVersion))
	target := installed(t)
	opts := baseOpts(url, signer, target)
	opts.TrustedKeys = nil // built-in slots
	if _, err := Update(context.Background(), opts); !errors.Is(err, ErrNoTrustedKeys) {
		t.Fatalf("err = %v, want ErrNoTrustedKeys", err)
	}
	assertUnchanged(t, target)
}

func TestCheckReportsAvailability(t *testing.T) {
	signer := newTestSigner(1)
	r, url := newRelease(t, signer, fakeBinary(newVersion))
	res, err := Check(context.Background(), Options{BaseURL: url, CurrentVersion: oldVersion, Target: installed(t)})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !res.UpdateAvailable || res.To != newVersion {
		t.Errorf("result = %+v", res)
	}
	if r.requested("checksums.txt") {
		t.Errorf("--check fetched more than metadata.json")
	}

	res, err = Check(context.Background(), Options{BaseURL: url, CurrentVersion: "v2.0.0"})
	if err != nil || res.UpdateAvailable {
		t.Errorf("ahead of latest: res=%+v err=%v", res, err)
	}
	// A dev build is always behind.
	if res, _ = Check(context.Background(), Options{BaseURL: url, CurrentVersion: "dev"}); !res.UpdateAvailable {
		t.Errorf("dev build should be behind")
	}
}

func TestMetadataVersionValidated(t *testing.T) {
	r := &release{files: map[string][]byte{"metadata.json": []byte(`{"version":"../../etc"}`)}}
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()
	if _, err := Check(context.Background(), Options{BaseURL: srv.URL, CurrentVersion: oldVersion}); err == nil {
		t.Fatal("expected an invalid-version error")
	}
}

func TestBaseURLMustBeHTTPS(t *testing.T) {
	for base, ok := range map[string]bool{
		"https://cdn.example.com/rel": true,
		"http://127.0.0.1:8080":       true,
		"http://localhost:1":          true,
		"http://cdn.example.com/rel":  false,
		"ftp://cdn.example.com":       false,
	} {
		if err := checkBaseURL(base); (err == nil) != ok {
			t.Errorf("checkBaseURL(%q) err=%v, want ok=%v", base, err, ok)
		}
	}
}

// --- archive + replace helpers -----------------------------------------------

func TestExtractZipForWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.zip")
	if err := os.WriteFile(path, zipArchive(t, tarEntry{"LICENSE", []byte("l")}, tarEntry{"vigolium.exe", []byte("MZ-binary")}), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := extractBinary(path, "windows", &out, 1024); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if out.String() != "MZ-binary" {
		t.Errorf("got %q", out.String())
	}
	out.Reset()
	if err := extractBinary(path, "windows", &out, 4); err == nil {
		t.Errorf("expected a size-limit error")
	}
}

func TestReplaceViaOld(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "vigolium.exe")
	tmp := filepath.Join(dir, tempPrefix+"x.exe")
	_ = os.WriteFile(target, []byte("old"), 0o755)
	_ = os.WriteFile(tmp, []byte("new"), 0o755)
	if err := replaceViaOld(tmp, target); err != nil {
		t.Fatalf("replaceViaOld: %v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "new" {
		t.Errorf("target = %q", got)
	}
	CleanupOld(target)
	if _, err := os.Stat(target + ".old"); !os.IsNotExist(err) {
		t.Errorf(".old not cleaned up")
	}

	// A failed second rename puts the original back.
	if err := replaceViaOld(filepath.Join(dir, "missing"), target); err == nil {
		t.Fatal("expected an error for a missing temp file")
	}
	if got, _ := os.ReadFile(target); string(got) != "new" {
		t.Errorf("rollback lost the target: %q", got)
	}
}

func TestReportedVersionShapes(t *testing.T) {
	for out, want := range map[string]string{
		`{"version":"v1.2.3"}`:                         "v1.2.3",
		`{"ok":true,"items":[{"version":"v1.2.3"}]}`:   "v1.2.3",
		"banner\n{\"version\":\"1.2.3\",\"commit\":1}": "1.2.3",
	} {
		got, err := reportedVersion([]byte(out))
		if err != nil || got != want {
			t.Errorf("reportedVersion(%q) = %q, %v; want %q", out, got, err, want)
		}
	}
	if _, err := reportedVersion([]byte(`{"ok":true}`)); err == nil {
		t.Errorf("expected an error without a version")
	}
}

func TestLookupChecksum(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	data := []byte(sum + "  vigolium_1.2.3_linux_amd64.tar.gz\n" + sum + " *vigolium_1.2.3_windows_amd64.zip\nbad line\n")
	if got, ok := lookupChecksum(data, "vigolium_1.2.3_windows_amd64.zip"); !ok || got != sum {
		t.Errorf("binary-mode line: %q %v", got, ok)
	}
	if _, ok := lookupChecksum(data, "vigolium_1.2.3_darwin_arm64.tar.gz"); ok {
		t.Errorf("unlisted archive found")
	}
	if _, ok := lookupChecksum([]byte("zz  a.tar.gz\n"), "a.tar.gz"); ok {
		t.Errorf("malformed digest accepted")
	}
}
