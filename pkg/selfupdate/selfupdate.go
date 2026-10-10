// Package selfupdate replaces the running vigolium binary with a newer signed
// release, in process: no shell, no curl, no install script.
//
// Every file comes from one base URL (the CDN release prefix), so the version
// pointer, the checksums and the archive cannot skew against each other:
//
//  1. metadata.json names the target version;
//  2. checksums.txt and checksums.txt.minisig are fetched and the signature is
//     verified against the built-in release keys (keys.go), failing closed. The
//     signature's trusted comment must name the target version;
//  3. vigolium_<v>_<os>_<arch>.tar.gz (.zip on Windows) is downloaded to a temp
//     file in the target's own directory and must match its signed sha256;
//  4. the single vigolium entry is extracted with a size cap, and
//     `<tmp> version --json` must report the target version;
//  5. the temp binary is renamed over the target (os.Executable resolved
//     through symlinks), atomically on unix and via target.old on Windows.
//
// A target directory the user cannot write is an error that names the fix
// (sudo or --install-dir); nothing is silently installed somewhere else.
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/mod/semver"
)

const (
	// DefaultBaseURL is the public release prefix on the CDN; `make
	// public-release` uploads metadata.json, checksums.txt, its .minisig and
	// the archives there.
	DefaultBaseURL = "https://cdn.vigolium.com/vigolium-release"

	// EnvBaseURL overrides the release prefix (for example the nightly prefix,
	// https://cdn.vigolium.com/vigolium-nightly-release). Signatures are still
	// required, so pointing it elsewhere cannot install an unsigned build.
	EnvBaseURL = "VIGOLIUM_UPDATE_BASE_URL"

	// DefaultMaxArchiveBytes caps the archive download; DefaultMaxBinaryBytes
	// caps the extracted binary. Release binaries embed their helpers and run
	// to a few hundred MiB, so both leave ample room while still bounding a
	// hostile or corrupt stream.
	DefaultMaxArchiveBytes int64 = 1 << 30
	DefaultMaxBinaryBytes  int64 = 1 << 30

	maxMetadataBytes  = 64 << 10
	maxChecksumsBytes = 1 << 20
	maxSignatureBytes = 16 << 10

	tempPrefix = ".vigolium-update-"
)

// Options configures Check and Update. The zero value updates the running
// binary from DefaultBaseURL (or $VIGOLIUM_UPDATE_BASE_URL).
type Options struct {
	// BaseURL is the release prefix. "" uses $VIGOLIUM_UPDATE_BASE_URL, then
	// DefaultBaseURL. It must be https (plain http only to a loopback host).
	BaseURL string
	// CurrentVersion is the running binary's version ("v0.5.2"). A value that
	// is not semver (a dev build) is always treated as behind.
	CurrentVersion string
	// Target is the binary to replace. "" resolves the running executable
	// through symlinks.
	Target string
	// InstallDir, when set, installs <InstallDir>/vigolium instead of replacing
	// Target. The directory is created when missing.
	InstallDir string
	// GOOS/GOARCH select the archive; "" uses the running platform.
	GOOS, GOARCH string
	// DryRun resolves the version, verifies the signed checksums and probes
	// that the target is writable, but downloads and replaces nothing.
	DryRun bool

	// Client is the HTTP client; nil uses a client with a 10 minute timeout.
	Client *http.Client
	// TrustedKeys overrides the built-in release keys. For tests only.
	TrustedKeys []string
	// MaxArchiveBytes / MaxBinaryBytes override the size caps (0 = default).
	MaxArchiveBytes int64
	MaxBinaryBytes  int64
	// VerifyBinary checks the extracted binary before it replaces anything.
	// nil runs `<path> version --json` and compares the reported version.
	VerifyBinary func(ctx context.Context, path, wantVersion string) error
	// Logf receives one line per step for human progress output. Optional.
	Logf func(format string, args ...any)
}

// Result describes what Check or Update found and did.
type Result struct {
	From            string `json:"from"`
	To              string `json:"to"`
	Path            string `json:"path"`
	BaseURL         string `json:"base_url"`
	UpdateAvailable bool   `json:"update_available"`
	Changed         bool   `json:"changed"`
	DryRun          bool   `json:"dry_run,omitempty"`
	Archive         string `json:"archive,omitempty"`
	SHA256          string `json:"sha256,omitempty"`
}

// NotWritableError is returned when the target's directory cannot be written.
type NotWritableError struct {
	Path string
	Err  error
}

func (e *NotWritableError) Error() string {
	return fmt.Sprintf("binary at %s is not writable (%v); re-run with sudo, or pass --install-dir <dir> to install a copy in a directory you own",
		e.Path, e.Err)
}

func (e *NotWritableError) Unwrap() error { return e.Err }

// Check resolves the latest release version and whether it is newer than the
// running one. It fetches metadata.json only: nothing is verified or written.
func Check(ctx context.Context, opts Options) (Result, error) {
	u, err := newUpdater(opts)
	if err != nil {
		return Result{}, err
	}
	res := Result{From: normalize(opts.CurrentVersion), BaseURL: u.base}
	latest, err := u.fetchVersion(ctx)
	if err != nil {
		return res, err
	}
	res.To = latest
	res.UpdateAvailable, err = newer(opts.CurrentVersion, latest)
	if err != nil {
		return res, err
	}
	if target, terr := u.target(); terr == nil {
		res.Path = target
	}
	return res, nil
}

// Update installs the latest signed release over the target binary (see the
// package doc for the steps). When the running version is already current it
// returns Changed=false without downloading anything.
func Update(ctx context.Context, opts Options) (Result, error) {
	u, err := newUpdater(opts)
	if err != nil {
		return Result{}, err
	}
	res := Result{From: normalize(opts.CurrentVersion), BaseURL: u.base, DryRun: opts.DryRun}

	u.logf("resolving latest release from %s/metadata.json", u.base)
	latest, err := u.fetchVersion(ctx)
	if err != nil {
		return res, err
	}
	res.To = latest
	if res.UpdateAvailable, err = newer(opts.CurrentVersion, latest); err != nil {
		return res, err
	}
	target, err := u.target()
	if err != nil {
		return res, err
	}
	res.Path = target
	if !res.UpdateAvailable {
		return res, nil
	}

	// Fail on an unwritable target before downloading hundreds of MiB.
	dir := filepath.Dir(target)
	if err := probeWritable(dir, target); err != nil {
		return res, err
	}

	archive := archiveName(latest, u.goos, u.goarch)
	res.Archive = archive
	u.logf("verifying signed checksums.txt")
	sum, err := u.signedChecksum(ctx, latest, archive)
	if err != nil {
		return res, err
	}
	res.SHA256 = sum
	if opts.DryRun {
		return res, nil
	}

	binTmp, err := os.CreateTemp(dir, tempPrefix+"*"+exeSuffix(u.goos))
	if err != nil {
		return res, notWritable(target, err)
	}
	binPath := binTmp.Name()
	installed := false
	defer func() {
		_ = binTmp.Close()
		if !installed {
			_ = os.Remove(binPath)
		}
	}()

	u.logf("downloading %s", archive)
	archivePath, err := u.download(ctx, dir, archive, sum)
	if err != nil {
		return res, err
	}
	defer func() { _ = os.Remove(archivePath) }()

	if err := extractBinary(archivePath, u.goos, binTmp, u.maxBinary); err != nil {
		return res, err
	}
	if err := binTmp.Close(); err != nil {
		return res, err
	}
	if err := os.Chmod(binPath, 0o755); err != nil {
		return res, err
	}

	u.logf("checking the new binary reports %s", latest)
	if err := u.verifyBinary(ctx, binPath, latest); err != nil {
		return res, err
	}

	u.logf("replacing %s", target)
	if err := replaceFile(u.goos, binPath, target); err != nil {
		return res, notWritable(target, err)
	}
	installed = true
	res.Changed = true
	return res, nil
}

// ResolveExecutable returns the running binary's path with symlinks resolved:
// the file an in-place update must replace (not the symlink in $PATH).
func ResolveExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	return filepath.Clean(exe), nil
}

// CleanupOld removes the <exe>.old file a Windows update leaves behind (the
// replaced binary cannot be deleted while it is still running). Best effort;
// a no-op everywhere else.
func CleanupOld(exe string) {
	if exe == "" {
		return
	}
	_ = os.Remove(exe + ".old")
}

// BinaryName is the executable's file name on goos.
func BinaryName(goos string) string { return "vigolium" + exeSuffix(goos) }

type updater struct {
	opts       Options
	base       string
	goos       string
	goarch     string
	client     *http.Client
	keys       []string
	maxArchive int64
	maxBinary  int64
}

func newUpdater(opts Options) (*updater, error) {
	base := strings.TrimSpace(opts.BaseURL)
	if base == "" {
		base = strings.TrimSpace(os.Getenv(EnvBaseURL))
	}
	if base == "" {
		base = DefaultBaseURL
	}
	base = strings.TrimRight(base, "/")
	if err := checkBaseURL(base); err != nil {
		return nil, err
	}
	u := &updater{
		opts:       opts,
		base:       base,
		goos:       firstNonEmpty(opts.GOOS, runtime.GOOS),
		goarch:     firstNonEmpty(opts.GOARCH, runtime.GOARCH),
		client:     opts.Client,
		keys:       opts.TrustedKeys,
		maxArchive: opts.MaxArchiveBytes,
		maxBinary:  opts.MaxBinaryBytes,
	}
	if u.client == nil {
		u.client = &http.Client{Timeout: 10 * time.Minute}
	}
	if u.keys == nil {
		u.keys = trustedKeys
	}
	if u.maxArchive <= 0 {
		u.maxArchive = DefaultMaxArchiveBytes
	}
	if u.maxBinary <= 0 {
		u.maxBinary = DefaultMaxBinaryBytes
	}
	return u, nil
}

// checkBaseURL requires https, allowing plain http only to a loopback host
// (local mirrors and tests). The signature is the real protection, but TLS
// keeps the version pointer from being swapped in transit.
func checkBaseURL(base string) error {
	u, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("invalid update base URL %q: %w", base, err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("update base URL %q must use https", base)
}

func (u *updater) logf(format string, args ...any) {
	if u.opts.Logf != nil {
		u.opts.Logf(format, args...)
	}
}

// target is the file to replace: <InstallDir>/vigolium when set, else the
// explicit Target, else the running executable.
func (u *updater) target() (string, error) {
	if dir := strings.TrimSpace(u.opts.InstallDir); dir != "" {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return "", err
		}
		if err := os.MkdirAll(abs, 0o755); err != nil {
			return "", notWritable(filepath.Join(abs, BinaryName(u.goos)), err)
		}
		return filepath.Join(abs, BinaryName(u.goos)), nil
	}
	if u.opts.Target != "" {
		t := u.opts.Target
		if resolved, err := filepath.EvalSymlinks(t); err == nil {
			t = resolved
		}
		return filepath.Abs(t)
	}
	return ResolveExecutable()
}

// fetchVersion reads metadata.json's version and validates it is semver, so it
// is safe to splice into the archive name.
func (u *updater) fetchVersion(ctx context.Context) (string, error) {
	data, err := u.get(ctx, "metadata.json", maxMetadataBytes, true)
	if err != nil {
		return "", err
	}
	var meta struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return "", fmt.Errorf("metadata.json: %w", err)
	}
	v := normalize(meta.Version)
	if !semver.IsValid(v) {
		return "", fmt.Errorf("metadata.json: version %q is not a valid release version", meta.Version)
	}
	return v, nil
}

// signedChecksum fetches checksums.txt and its .minisig, verifies the
// signature (and that its trusted comment names version), and returns the
// sha256 listed for archive.
func (u *updater) signedChecksum(ctx context.Context, version, archive string) (string, error) {
	sums, err := u.get(ctx, "checksums.txt", maxChecksumsBytes, true)
	if err != nil {
		return "", err
	}
	sig, err := u.get(ctx, "checksums.txt.minisig", maxSignatureBytes, true)
	if err != nil {
		return "", fmt.Errorf("release is not signed: %w", err)
	}
	comment, err := verifyMinisign(u.keys, sums, sig)
	if err != nil {
		return "", err
	}
	if !commentNamesVersion(comment, version) {
		return "", fmt.Errorf("%w: signature is for %q, not %s", ErrBadSignature, comment, version)
	}
	sum, ok := lookupChecksum(sums, archive)
	if !ok {
		return "", fmt.Errorf("signed checksums.txt does not list %s (no build for this platform?)", archive)
	}
	return sum, nil
}

// download streams archive into a temp file in dir, enforcing the size cap and
// the expected sha256. The caller removes the returned path.
func (u *updater) download(ctx context.Context, dir, archive, wantSum string) (string, error) {
	resp, err := u.open(ctx, archive, false)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.ContentLength > u.maxArchive {
		return "", fmt.Errorf("%s is %d bytes, over the %d byte limit", archive, resp.ContentLength, u.maxArchive)
	}
	f, err := os.CreateTemp(dir, tempPrefix+"*.download")
	if err != nil {
		return "", notWritable(dir, err)
	}
	path := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, u.maxArchive+1))
	if err != nil {
		return "", fmt.Errorf("download %s: %w", archive, err)
	}
	if n > u.maxArchive {
		return "", fmt.Errorf("%s exceeds the %d byte limit", archive, u.maxArchive)
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, wantSum) {
		return "", fmt.Errorf("%s sha256 mismatch: signed checksums.txt says %s, downloaded file is %s", archive, wantSum, got)
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ok = true
	return path, nil
}

func (u *updater) verifyBinary(ctx context.Context, path, version string) error {
	if u.opts.VerifyBinary != nil {
		return u.opts.VerifyBinary(ctx, path, version)
	}
	return runVersionCheck(ctx, path, version)
}

// get fetches a small file fully, capped at limit bytes.
func (u *updater) get(ctx context.Context, name string, limit int64, bust bool) ([]byte, error) {
	resp, err := u.open(ctx, name, bust)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", name, limit)
	}
	return data, nil
}

// open GETs base/name. bust appends a cache-busting query so a CDN edge never
// pairs a fresh metadata.json with a stale checksums.txt.
func (u *updater) open(ctx context.Context, name string, bust bool) (*http.Response, error) {
	target := u.base + "/" + name
	if bust {
		target += "?t=" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "vigolium-selfupdate")
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", name, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("fetch %s/%s: HTTP %d", u.base, name, resp.StatusCode)
	}
	return resp, nil
}

// probeWritable creates and removes a temp file in dir.
func probeWritable(dir, target string) error {
	f, err := os.CreateTemp(dir, tempPrefix+"probe-*")
	if err != nil {
		return notWritable(target, err)
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

// notWritable wraps permission-class errors in NotWritableError and passes
// anything else through.
func notWritable(target string, err error) error {
	if errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EROFS) {
		return &NotWritableError{Path: target, Err: err}
	}
	return err
}

// replaceFile moves tmp over target. On unix rename(2) is atomic and the
// running process keeps its (now unlinked) inode. Windows cannot rename over
// a running executable, but it can rename the running file itself, so the
// target steps aside to target.old first (CleanupOld removes it next start).
func replaceFile(goos, tmp, target string) error {
	if goos != "windows" {
		return os.Rename(tmp, target)
	}
	return replaceViaOld(tmp, target)
}

func replaceViaOld(tmp, target string) error {
	old := target + ".old"
	_ = os.Remove(old)
	movedAside := false
	if err := os.Rename(target, old); err == nil {
		movedAside = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		if movedAside {
			_ = os.Rename(old, target)
		}
		return err
	}
	if movedAside {
		_ = os.Remove(old) // fails while the old binary runs; CleanupOld retries
	}
	return nil
}

// newer reports whether latest is strictly newer than current. A current
// version that is not semver (a dev build) is always behind.
func newer(current, latest string) (bool, error) {
	l := normalize(latest)
	if !semver.IsValid(l) {
		return false, fmt.Errorf("latest version %q is not valid semver", latest)
	}
	c := normalize(current)
	if !semver.IsValid(c) {
		return true, nil
	}
	return semver.Compare(l, c) > 0, nil
}

// commentNamesVersion reports whether a trusted comment such as
// "vigolium v0.5.3" names version (with or without the leading v).
func commentNamesVersion(comment, version string) bool {
	want := normalize(version)
	for _, f := range strings.Fields(comment) {
		if normalize(f) == want {
			return true
		}
	}
	return false
}

// lookupChecksum finds name's sha256 in a `<hex>  <name>` checksums file.
func lookupChecksum(data []byte, name string) (string, bool) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if strings.TrimPrefix(fields[1], "*") != name {
			continue
		}
		sum := strings.ToLower(fields[0])
		if len(sum) != sha256.Size*2 {
			return "", false
		}
		if _, err := hex.DecodeString(sum); err != nil {
			return "", false
		}
		return sum, true
	}
	return "", false
}

func archiveName(version, goos, goarch string) string {
	ext := "tar.gz"
	if goos == "windows" {
		ext = "zip"
	}
	return fmt.Sprintf("vigolium_%s_%s_%s.%s", strings.TrimPrefix(version, "v"), goos, goarch, ext)
}

func exeSuffix(goos string) string {
	if goos == "windows" {
		return ".exe"
	}
	return ""
}

func normalize(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
