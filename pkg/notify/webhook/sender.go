// Package webhook fires a single HTTP POST when a scan reaches a terminal
// state (completed, failed or cancelled). Unlike the per-finding notify
// backends, this is a one-shot scan-completion hook: project-scoped, retried
// up to 5 times on 5xx/network errors, and asynchronous so it never blocks the
// scan. A short-lived process (the CLI) calls Drain before it exits so the POST
// is not lost with the process; a long-lived one (the server) never needs to.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"go.uber.org/zap"
)

const maxRetries = 5

// initialBackoff is the first inter-attempt delay; it doubles each retry.
// A var (not const) so tests can shrink it to keep retry coverage fast.
var initialBackoff = time.Second

// FindingCounts is the severity breakdown of findings produced by a scan.
type FindingCounts struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
}

// ScanCompletedPayload is the JSON body POSTed to the webhook URL. The name
// predates the failed/cancelled events; every terminal outcome uses it.
type ScanCompletedPayload struct {
	// Event is scan.completed, scan.failed or scan.cancelled (see EventFor*).
	Event       string `json:"event"`
	ProjectUUID string `json:"project_uuid"`
	ScanUUID    string `json:"scan_uuid"`
	ScanType    string `json:"scan_type"`
	Target      string `json:"target"`
	Status      string `json:"status"`
	// Completeness is "complete" or "partial" when the run knows (a curtailed
	// scan is still scan.completed, with completeness "partial"); StopReason
	// names why it stopped short. Both empty when unknown.
	Completeness string `json:"completeness,omitempty"`
	StopReason   string `json:"stop_reason,omitempty"`
	// Error is the failure message on scan.failed.
	Error      string        `json:"error,omitempty"`
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at"`
	Findings   FindingCounts `json:"findings"`
	ResultURL  string        `json:"result_url"`
}

// Sender posts ScanCompletedPayload to a configured URL with retry on 5xx.
type Sender struct {
	cfg        config.WebhookConfig
	httpClient *http.Client
}

// NewSender returns a Sender or nil when the webhook URL is empty.
// Provider/master-switch gating is the caller's responsibility — this
// helper only validates the per-channel config.
func NewSender(cfg config.WebhookConfig) *Sender {
	if !cfg.IsConfigured() {
		return nil
	}
	return &Sender{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.EffectiveTimeout()) * time.Second,
		},
	}
}

// Post sends the payload with retries (5 attempts, exponential backoff on
// 5xx and network errors). 4xx responses are not retried. Returns the last
// error encountered when all attempts fail.
func (s *Sender) Post(ctx context.Context, payload ScanCompletedPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	var lastErr error
	backoff := initialBackoff
	for attempt := 1; attempt <= maxRetries; attempt++ {
		retry, err := s.attempt(ctx, body)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retry || attempt == maxRetries {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return lastErr
}

// attempt sends one POST. The bool reports whether the error is retryable.
func (s *Sender) attempt(ctx context.Context, body []byte) (retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.Authorization != "" {
		req.Header.Set("Authorization", s.cfg.Authorization)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return true, fmt.Errorf("post webhook: %w", redactURLError(err))
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, nil
	}
	if resp.StatusCode >= 500 {
		return true, fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return false, fmt.Errorf("webhook returned %d", resp.StatusCode)
}

// redactURLError walks an http.Client error chain looking for *url.Error
// wrappers and rewrites their URL field so a webhook token embedded in
// the path or query (Slack hooks.slack.com/services/T../B../XXX, Discord,
// Teams) doesn't leak into the wrapped error message. Returns the original
// error untouched when it isn't a *url.Error.
func redactURLError(err error) error {
	var ue *url.Error
	if !errors.As(err, &ue) {
		return err
	}
	return &url.Error{Op: ue.Op, URL: redactURL(ue.URL), Err: ue.Err}
}

// redactURL keeps the scheme, host, and port visible (so operators can
// tell *which* upstream failed) and replaces the path + query + fragment
// with a placeholder. Returns the input unchanged when it isn't a valid
// URL — better to log a malformed string than swallow it.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<redacted-url>"
	}
	u.Path = "/<redacted>"
	u.RawQuery = ""
	u.Fragment = ""
	u.User = nil
	return u.String()
}

// inflight counts PostAsync deliveries not yet finished, so Drain can wait for
// them and say how many it gave up on. A counter rather than a WaitGroup: the
// server fires while other goroutines may be draining in tests, and a
// WaitGroup's Add-from-zero must not race a Wait.
var inflight atomic.Int64

// drainPoll is how often Drain re-checks the in-flight count.
const drainPoll = 10 * time.Millisecond

// PostAsync fires the POST in a goroutine and logs failures. Use this from
// scan-completion paths so the scan does not block on webhook delivery. The
// delivery is tracked for Drain.
func (s *Sender) PostAsync(payload ScanCompletedPayload) {
	inflight.Add(1)
	go func() {
		defer inflight.Add(-1)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := s.Post(ctx, payload); err != nil {
			zap.L().Warn("[Notify] Webhook delivery failed",
				zap.String("scan_uuid", payload.ScanUUID),
				zap.String("scan_type", payload.ScanType),
				zap.Error(err))
			return
		}
		zap.L().Info("[Notify] Webhook delivered",
			zap.String("scan_uuid", payload.ScanUUID),
			zap.String("scan_type", payload.ScanType))
	}()
}

// Drain waits up to timeout for every PostAsync delivery started so far to
// finish (delivered, or failed after its retries) and returns how many were
// still in flight when it gave up. A process that is about to exit calls it so
// its webhooks are not killed mid-POST; 0 means nothing was left behind.
func Drain(timeout time.Duration) (undelivered int) {
	deadline := time.Now().Add(timeout)
	for {
		n := inflight.Load()
		if n <= 0 {
			return 0
		}
		if !time.Now().Before(deadline) {
			return int(n)
		}
		time.Sleep(min(drainPoll, time.Until(deadline)))
	}
}
