package services

import (
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/notify"
	"github.com/vigolium/vigolium/pkg/types"
	"golang.org/x/time/rate"
)

// Services contains runtime services used across the application.
type Services struct {
	// Options contains CLI configuration
	Options *types.Options

	// HostLimiter limits concurrent requests per hostname
	HostLimiter *hostlimit.HostRateLimiter

	// RateLimiter, when non-nil, caps the GLOBAL outbound request rate (requests
	// per second) across all hosts — distinct from HostLimiter's per-host
	// concurrency. It is on by default: Options.RateLimit carries the documented
	// 100 rps default (scanning_pace.rate_limit) even when --rate-limit is not
	// typed, and only a rate of 0 ("unlimited") leaves it nil. Shared across every
	// Requester built from these Services (and their WithContext clones), so one
	// token bucket governs the whole scan.
	RateLimiter *rate.Limiter

	// HostErrors tracks host failures for circuit breaking
	HostErrors *hosterrors.Cache

	// Notifier sends notifications (Telegram, Discord, etc.)
	Notifier *notify.Manager

	// Dialer is the fastdialer instance for DNS resolution
	Dialer *fastdialer.Dialer

	// DedupManager manages deduplication for modules
	DedupManager *dedup.Manager
}
