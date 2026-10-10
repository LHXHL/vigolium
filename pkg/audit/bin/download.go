package bin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/helperblob"
)

// BaseURLEnv sets the download base URL for `audit_external` builds. The URL
// must be https and serve vigolium-audit_<sha12>_<os>_<arch>.zst, the assets
// `make audit-external-pins` writes. Overrides the link-time default.
const BaseURLEnv = "VIGOLIUM_AUDIT_BASE_URL"

// defaultBaseURL is the download base URL compiled into an `audit_external`
// build, set with
//
//	-ldflags "-X github.com/vigolium/vigolium/pkg/audit/bin.defaultBaseURL=https://…"
//
// It is empty by default: no CDN hosts the helpers yet, so a build without it
// needs VIGOLIUM_AUDIT_BASE_URL (or VIGOLIUM_AUDIT_BINARY).
var defaultBaseURL = ""

// externalPins maps "<goos>_<goarch>" to the pinned helper. It is populated
// only by the generated pins_gen.go in `audit_external` builds.
var externalPins map[string]helperblob.Pin

// httpClient fetches helpers; tests swap it for an httptest TLS client.
var httpClient = &http.Client{Timeout: 10 * time.Minute}

// unavailableHint is the remediation appended to every ErrHelperUnavailable.
const unavailableHint = "set " + BaseURLEnv + "=https://<mirror> to a host serving the pinned helper, " +
	"or " + BinaryEnv + "=/path/to/vigolium-audit for an offline install; " +
	"`vigolium doctor --fix --only vigolium-audit` prefetches it once online"

// downloadSource fetches the pinned helper over https (`audit_external`).
type downloadSource struct{}

func (downloadSource) kind() string { return SourceDownload }

func (downloadSource) pin() (helperblob.Pin, error) {
	key := runtime.GOOS + "_" + runtime.GOARCH
	pin, ok := externalPins[key]
	if !ok {
		return helperblob.Pin{}, fmt.Errorf("%w: this audit_external build pins no vigolium-audit for %s/%s (generate pkg/audit/bin/pins_gen.go with `make audit-external-pins`), or set %s",
			ErrBinaryMissing, runtime.GOOS, runtime.GOARCH, BinaryEnv)
	}
	if err := pin.Validate(); err != nil {
		return helperblob.Pin{}, err
	}
	return pin, nil
}

func (downloadSource) open(ctx context.Context, pin helperblob.Pin) (io.ReadCloser, error) {
	return download(ctx, pin)
}

func (downloadSource) ready(pin helperblob.Pin) bool {
	_, err := downloadURL(pin)
	return err == nil
}

func (downloadSource) origin(pin helperblob.Pin) string {
	u, err := downloadURL(pin)
	if err != nil {
		return "(no download URL: " + err.Error() + ")"
	}
	return u
}

// assetName is the content-addressed file name of a helper download.
func assetName(pin helperblob.Pin) string {
	return fmt.Sprintf("vigolium-audit_%s_%s_%s.zst", pin.Short(), runtime.GOOS, runtime.GOARCH)
}

// downloadURL resolves the helper URL, refusing anything but https.
func downloadURL(pin helperblob.Pin) (string, error) {
	base := os.Getenv(BaseURLEnv)
	if base == "" {
		base = defaultBaseURL
	}
	if base == "" {
		return "", fmt.Errorf("%w: no download base URL configured; %s", ErrHelperUnavailable, unavailableHint)
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("%w: download base URL %q must be an https URL; %s", ErrHelperUnavailable, base, unavailableHint)
	}
	return strings.TrimRight(base, "/") + "/" + assetName(pin), nil
}

// download opens the compressed helper stream. The caller (helperblob.Install)
// verifies the decompressed bytes against the pin, so the transport only has
// to be https; redirects to anything else are refused.
func download(ctx context.Context, pin helperblob.Pin) (io.ReadCloser, error) {
	target, err := downloadURL(pin)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w; %s", ErrHelperUnavailable, err, unavailableHint)
	}
	client := *httpClient
	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if r.URL.Scheme != "https" {
			return fmt.Errorf("refusing redirect to non-https %s", r.URL.Redacted())
		}
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: download %s: %w; %s", ErrHelperUnavailable, target, err, unavailableHint)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: download %s: HTTP %d; %s", ErrHelperUnavailable, target, resp.StatusCode, unavailableHint)
	}
	// A compressed helper is far smaller than the executable; the slack covers
	// zstd framing on an incompressible payload.
	return limitedBody{Reader: io.LimitReader(resp.Body, pin.Size+1<<20), Closer: resp.Body}, nil
}

type limitedBody struct {
	io.Reader
	io.Closer
}
