package server

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/verify"
)

// VerifyFindingRequest is the optional JSON body for
// POST /api/findings/:id/verify. Every field mirrors a `finding verify` flag.
type VerifyFindingRequest struct {
	// DryRun returns the reconstruction (module, baseline request, insertion
	// point) without sending or writing anything.
	DryRun bool `json:"dry_run,omitempty"`
	// NoWrite runs the verification without storing the verdict.
	NoWrite bool `json:"no_write,omitempty"`
	// Mark also sets the status: not_reproduced → false_positive,
	// confirmed → confirmed.
	Mark bool `json:"mark,omitempty"`
	// Refetch makes a passive finding fetch a fresh response instead of
	// re-analyzing the stored one.
	Refetch bool `json:"refetch,omitempty"`
	// RateLimit is max requests/second (0 = unlimited; fractions allowed).
	RateLimit float64 `json:"rate_limit,omitempty"`
	// Timeout bounds the verification, a Go duration ("2m" default, at most
	// "10m"). One request is capped at 15s.
	Timeout string `json:"timeout,omitempty"`
}

// maxVerifyTimeout bounds a REST verification: the request is answered
// synchronously, so the caller's connection stays open for the whole run.
const maxVerifyTimeout = 10 * time.Minute

// findingVerifyActorAPI is the actor recorded on status changes mark makes.
const findingVerifyActorAPI = "api:finding-verify"

// HandleVerifyFinding handles POST /api/findings/:id/verify — re-runs the
// module behind one finding (by numeric id or finding hash, 12+ char prefix)
// against its target and records whether it reproduces: `vigolium finding
// verify` over REST. The finding must belong to the request's project.
//
// The answer is the verify result (verdict, reason, plan, request count): the
// object itself in v1, a one-item list envelope with the verdict tally in v2.
func (h *Handlers) HandleVerifyFinding(c fiber.Ctx) error {
	if h.db == nil || h.repo == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}
	var req VerifyFindingRequest
	if len(c.Body()) > 0 {
		if err := c.Bind().JSON(&req); err != nil {
			return respondError(c, fiber.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		}
	}
	timeout, err := validateVerifyFindingRequest(req)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, err)
	}

	projectUUID := getProjectUUID(c)
	ctx := c.Context()
	f, err := h.resolveFindingRef(ctx, projectUUID, c.Params("id"))
	if err != nil {
		var amb *database.AmbiguousFindingHashError
		switch {
		case errors.As(err, &amb):
			return respondError(c, fiber.StatusBadRequest, amb)
		case errors.Is(err, ErrFindingNotFound):
			return respondError(c, fiber.StatusNotFound, ErrFindingNotFound)
		}
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to retrieve finding: %w", err))
	}

	var stack *verify.HTTPStack
	var stackErr error
	getStack := func() *verify.HTTPStack {
		if stack == nil && stackErr == nil {
			stack, stackErr = verify.NewHTTPStack(verify.HTTPConfig{
				ProxyURL:  h.serverProxyURL(),
				Timeout:   timeout,
				RateLimit: req.RateLimit,
			})
		}
		return stack
	}
	defer func() { stack.Close() }()

	var loadExt func() map[string]modules.Module
	if verify.NeedsExtensions(f) {
		loadExt = func() map[string]modules.Module { return h.verifyExtensionModules(projectUUID, getStack(), stackErr) }
	}
	plan := verify.Reconstruct(ctx, h.repo, projectUUID, f, verify.Resolver(loadExt))

	var res *verify.Result
	if req.DryRun {
		res = verify.DryRun(plan, req.Refetch)
	} else {
		opts := verify.RunOptions{Refetch: req.Refetch, Timeout: timeout}
		if plan.NeedsNetwork(req.Refetch) {
			if s := getStack(); s != nil {
				opts.Requester, opts.Services = s.Requester, s.Services
			} else {
				plan.Verdict, plan.Reason = database.VerdictInconclusive, "HTTP setup failed: "+stackErr.Error()
			}
		}
		res = verify.Run(ctx, plan, opts)
		if plan.Baseline != nil {
			plan.Baseline.Request = "" // shown by dry_run only
		}
		if !req.NoWrite && ctx.Err() == nil {
			verify.Record(ctx, h.repo, projectUUID, f, res, verify.RecordOptions{
				Mark:          req.Mark,
				Actor:         findingVerifyActorAPI,
				ModuleVersion: h.config.Version,
			})
		}
	}

	counts := make(map[string]int, len(database.VerificationVerdicts))
	for _, v := range database.VerificationVerdicts {
		counts[v] = 0
	}
	if res.Verdict != "" {
		counts[res.Verdict]++
	}
	return respondMutationList(c, res, PaginatedResponse{
		Data:        []*verify.Result{res},
		Total:       1,
		ProjectUUID: projectUUID,
	}, map[string]any{
		"changed":  res.Written,
		"action":   "verify",
		"dry_run":  req.DryRun,
		"written":  !req.DryRun && !req.NoWrite,
		"verdicts": counts,
	})
}

// validateVerifyFindingRequest rejects contradictory or out-of-range options
// (the CLI's usage errors) and returns the run's time bound.
func validateVerifyFindingRequest(req VerifyFindingRequest) (time.Duration, error) {
	if req.Mark && (req.DryRun || req.NoWrite) {
		return 0, errors.New("mark writes the status, so it cannot be combined with dry_run or no_write")
	}
	if req.RateLimit < 0 {
		return 0, errors.New("rate_limit must be >= 0")
	}
	timeout := verify.DefaultTimeout
	if s := strings.TrimSpace(req.Timeout); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return 0, fmt.Errorf("invalid timeout %q: %w", req.Timeout, err)
		}
		if d <= 0 || d > maxVerifyTimeout {
			return 0, fmt.Errorf("timeout must be > 0 and at most %s", maxVerifyTimeout)
		}
		timeout = d
	}
	return timeout, nil
}

// resolveFindingRef loads the finding ref names within projectUUID: a numeric
// id, else a finding hash or 12+ char prefix. A finding outside the project is
// ErrFindingNotFound, exactly like a missing one.
func (h *Handlers) resolveFindingRef(ctx context.Context, projectUUID, ref string) (*database.Finding, error) {
	ref = strings.TrimSpace(ref)
	var ids []int64
	var hashes []string
	if id, err := strconv.ParseInt(ref, 10, 64); err == nil {
		ids = []int64{id}
	} else if ref != "" {
		hashes = []string{ref}
	}
	if len(ids) == 0 && len(hashes) == 0 {
		return nil, ErrFindingNotFound
	}
	found, _, err := h.repo.ResolveFindings(ctx, projectUUID, ids, hashes)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, ErrFindingNotFound
	}
	return found[0], nil
}

// serverProxyURL is the upstream proxy the server's own requester uses
// (vigolium server --proxy).
func (h *Handlers) serverProxyURL() string {
	if h.services != nil && h.services.Options != nil {
		return h.services.Options.ProxyURL
	}
	return ""
}

// verifyExtensionModules loads the project's configured extensions for an
// ext-* finding. nil (the finding is then unsupported) when they cannot load.
func (h *Handlers) verifyExtensionModules(projectUUID string, stack *verify.HTTPStack, stackErr error) map[string]modules.Module {
	if stack == nil {
		if stackErr != nil {
			zap.L().Warn("finding verify: extensions not loaded", zap.Error(stackErr))
		}
		return nil
	}
	settings, err := h.settingsForProject(projectUUID)
	if err != nil {
		zap.L().Warn("finding verify: extensions not loaded", zap.Error(err))
		return nil
	}
	ext, err := verify.LoadExtensionModules(&settings.DynamicAssessment.Extensions, stack.Requester)
	if err != nil {
		zap.L().Warn("finding verify: extensions not loaded", zap.Error(err))
		return nil
	}
	return ext
}
