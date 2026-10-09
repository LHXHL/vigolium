package harvester

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/sourcegraph/conc"
	"go.uber.org/zap"
)

// Built-in bounds, applied whenever an Options field is zero. They mirror the
// defaults in internal/config (external_harvester.*).
const (
	DefaultPerShape    = 3
	DefaultMaxURLs     = 5000
	DefaultCDXPageSize = 10000
	DefaultCDXMaxRows  = 200000
)

// LimitCDXMaxRows is the phase limit code a source reports when an archive
// index query stops at its row cap. It is the same string as
// database.LimitCDXMaxRows (drift-tested); it is restated here so this package
// does not import the database layer.
const LimitCDXMaxRows = "cdx_max_rows"

// Options bounds what a harvest keeps. Zero means the built-in default; a
// negative value disables that bound.
type Options struct {
	// PerShape is how many URLs are kept per shape (host + pathshape template
	// + sorted query names).
	PerShape int
	// MaxURLs is how many URLs are kept per harvested domain, after shaping.
	MaxURLs int
	// CDXPageSize is the rows requested per Wayback CDX resumeKey page.
	CDXPageSize int
	// CDXMaxRows caps the Wayback CDX index rows read per domain.
	CDXMaxRows int
}

// resolve turns the zero/negative convention into concrete bounds, where 0
// means "unbounded".
func (o Options) resolve() Options {
	pick := func(v, def int) int {
		switch {
		case v == 0:
			return def
		case v < 0:
			return 0
		}
		return v
	}
	return Options{
		PerShape:    pick(o.PerShape, DefaultPerShape),
		MaxURLs:     pick(o.MaxURLs, DefaultMaxURLs),
		CDXPageSize: pick(o.CDXPageSize, DefaultCDXPageSize),
		CDXMaxRows:  pick(o.CDXMaxRows, DefaultCDXMaxRows),
	}
}

// cdxTunable is implemented by sources that read a paged CDX index and accept
// the harvest's page size and row cap.
type cdxTunable interface {
	setCDXBounds(pageSize, maxRows int)
}

// Stats describes what one Harvest run received and what it kept. Raw counts
// every URL the sources reported; each later field is a disjoint reason a URL
// was not emitted, so Raw = Invalid + Static + Duplicate + OverShape +
// OverDomainCap + Kept.
type Stats struct {
	Raw           int
	Invalid       int
	Static        int
	Duplicate     int
	OverShape     int
	OverDomainCap int
	Kept          int
	Errors        int
	// Limits are the phase limit codes sources reported (sorted, unique).
	Limits []string
}

// Harvester orchestrates multiple sources to collect URLs for target domains.
type Harvester struct {
	sources []Source
	timeout time.Duration
	opts    Options // resolved

	mu    sync.Mutex
	stats Stats
}

// New creates a new Harvester with the given sources and timeout, using the
// default shaping bounds (see WithOptions).
func New(sources []Source, timeout time.Duration) *Harvester {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	h := &Harvester{
		sources: sources,
		timeout: timeout,
	}
	return h.WithOptions(Options{})
}

// WithOptions sets the shaping and CDX bounds and hands the CDX ones to every
// source that pages a CDX index. It returns h for chaining.
func (h *Harvester) WithOptions(o Options) *Harvester {
	h.opts = o.resolve()
	for _, s := range h.sources {
		if t, ok := s.(cdxTunable); ok {
			t.setCDXBounds(h.opts.CDXPageSize, h.opts.CDXMaxRows)
		}
	}
	return h
}

// Stats returns the counts of the most recent Harvest. It is complete once the
// channel Harvest returned has been closed.
func (h *Harvester) Stats() Stats {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.stats
	s.Limits = slices.Clone(s.Limits)
	return s
}

// domainResult is a Result tagged with the domain whose query produced it, so
// the per-domain cap counts subdomain URLs against the domain that was asked
// for.
type domainResult struct {
	Result
	domain string
}

// Harvest collects URLs from all sources for the given domains.
//
// Every URL is normalized (normalizeURL), deduplicated, then sampled: at most
// PerShape URLs per shape and MaxURLs per domain are kept. Kept URLs are
// streamed, in normalized form, to the returned channel, which is closed when
// all sources have finished or the timeout expires; Stats then reports raw vs
// kept counts and any limit a source hit.
func (h *Harvester) Harvest(ctx context.Context, domains []string) <-chan string {
	out := make(chan string, 100)

	go func() {
		defer close(out)

		ctx, cancel := context.WithTimeout(ctx, h.timeout)
		defer cancel()

		// Merge results from all sources across all domains
		merged := make(chan domainResult, 100)
		var wg conc.WaitGroup

		for _, src := range h.sources {
			for _, domain := range domains {
				s, d := src, domain
				wg.Go(func() {
					ch := s.Run(ctx, d)
					for r := range ch {
						select {
						case <-ctx.Done():
							return
						case merged <- domainResult{Result: r, domain: d}:
						}
					}
				})
			}
		}

		// Close merged channel when all sources are done
		go func() {
			defer close(merged)
			wg.Wait()
		}()

		sh := newShaper(h.opts)
		defer func() {
			h.mu.Lock()
			h.stats = sh.stats
			h.mu.Unlock()

			st := sh.stats
			zap.L().Info("Harvester completed",
				zap.Int("raw_urls", st.Raw),
				zap.Int("kept_urls", st.Kept),
				zap.Int("duplicate", st.Duplicate),
				zap.Int("static_dropped", st.Static),
				zap.Int("invalid", st.Invalid),
				zap.Int("over_per_shape", st.OverShape),
				zap.Int("over_max_urls", st.OverDomainCap),
				zap.Strings("limits", st.Limits),
				zap.Int("errors", st.Errors),
				zap.Int("sources", len(h.sources)),
				zap.Int("domains", len(domains)))
		}()

		for r := range merged {
			if r.Error != nil {
				sh.stats.Errors++
				zap.L().Debug("Harvester source error",
					zap.String("source", r.Source),
					zap.Error(r.Error))
				continue
			}
			if r.Limit != "" {
				sh.noteLimit(r.Limit)
				zap.L().Warn("Harvester source stopped at a limit",
					zap.String("source", r.Source),
					zap.String("domain", r.domain),
					zap.String("limit", r.Limit))
				continue
			}

			kept, ok := sh.admit(r.domain, r.URL)
			if !ok {
				continue
			}

			select {
			case <-ctx.Done():
				return
			case out <- kept:
			}
		}
	}()

	return out
}

// shaper applies normalization, dedup and sampling to a stream of harvested
// URLs. It is single-goroutine state owned by one Harvest run.
type shaper struct {
	opts      Options // resolved: 0 = unbounded
	seen      map[string]struct{}
	perShape  map[string]int
	perDomain map[string]int
	stats     Stats
}

func newShaper(opts Options) *shaper {
	return &shaper{
		opts:      opts,
		seen:      make(map[string]struct{}),
		perShape:  make(map[string]int),
		perDomain: make(map[string]int),
	}
}

// admit decides whether one harvested URL is kept, returning its normalized
// form when it is. The order — normalize, dedup, per-shape, per-domain — means
// the domain cap counts shaped survivors only, and a URL refused by the domain
// cap does not use up one of its shape's samples.
func (s *shaper) admit(domain, raw string) (string, bool) {
	s.stats.Raw++

	u, reason := normalizeURL(raw)
	switch reason {
	case dropInvalid:
		s.stats.Invalid++
		return "", false
	case dropStatic:
		s.stats.Static++
		return "", false
	}

	normalized := u.String()
	if _, dup := s.seen[normalized]; dup {
		s.stats.Duplicate++
		return "", false
	}
	s.seen[normalized] = struct{}{}

	key := shapeKey(u)
	if s.opts.PerShape > 0 && s.perShape[key] >= s.opts.PerShape {
		s.stats.OverShape++
		return "", false
	}
	if s.opts.MaxURLs > 0 && s.perDomain[domain] >= s.opts.MaxURLs {
		s.stats.OverDomainCap++
		return "", false
	}
	s.perShape[key]++
	s.perDomain[domain]++
	s.stats.Kept++
	return normalized, true
}

func (s *shaper) noteLimit(code string) {
	if !slices.Contains(s.stats.Limits, code) {
		s.stats.Limits = append(s.stats.Limits, code)
		slices.Sort(s.stats.Limits)
	}
}
